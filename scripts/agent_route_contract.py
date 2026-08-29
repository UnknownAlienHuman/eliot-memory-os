"""Contract checks shared by the agent-route bundle verifier."""
from __future__ import annotations

from pathlib import Path
from typing import Any

HOSTS = ("codex", "opencode", "claude", "antigravity")
PROFILE = "integrations/{host}/route-profile.json"
VERSION = "eliot.agent-route-profile.v1"
TOP = {
    "schema_version", "profile_id", "host_family", "route_class",
    "implementation_support", "evidence_execution_status", "architecture_anchors",
    "host_surfaces", "execution_routes", "skills", "mcp", "coordination",
    "probe_requirements", "known_gaps", "source_refs",
}
ROUTE = {
    "route_id", "role", "status", "transport", "execution_identity", "launch",
    "schema_and_health_probe", "model_selection", "session_control",
    "event_contract", "child_agents", "swarm", "proof_ceiling",
}
ROUTE_IDS = {
    "codex": {"codex.app-server.stdio"},
    "opencode": {"opencode.server.http-sse"},
    "claude": {"claude.agent-sdk.local-sidecar", "claude.managed-agents.remote"},
    "antigravity": {
        "antigravity.exec.persistent-ndjson",
        "antigravity.python-sdk.sidecar",
        "antigravity.agy.readonly-diff",
    },
}
SKILLS = {
    "canonical_source": "integrations/agent-skills", "delivery": "lazy",
    "index_payload": "name_and_trigger_description", "body_payload": "on_activation",
    "runtime_payload": "on_reference", "authority_ceiling": "none",
}
COORDINATION = {
    "attempt_state_owner": "eliot_agent_coordinator",
    "message_transport": "durable_mailbox",
    "meeting_form": "concilium_over_sealed_evidence",
    "decision_owner": "task_controller_or_human",
    "transcript_policy": "no_whole_sibling_transcript_by_default",
    "result_authority": "candidate_only_until_governed_transition",
}
SWARM = {
    "control_plane": "eliot.coordinate", "durable_mailbox": True,
    "direct_group_chat": False, "recursive_launch_default": "disabled",
    "context_policy": "minimum_decision_sufficient_packet",
}
Finding = tuple[str, str, str]


def add(out: list[Finding], code: str, path: str, detail: str) -> None:
    out.append((code, path, detail))


def route_errors(route: Any, where: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(route, dict):
        return [("route_invalid", where, "route must be an object")]
    missing = ROUTE - set(route)
    if missing:
        return [("route_required_gap", where, f"missing {sorted(missing)}")]
    launch = route.get("launch", {})
    if not isinstance(launch, dict) or launch.get("shell") is not False or launch.get("argv_construction") != "typed_no_shell":
        add(out, "route_shell_boundary_invalid", where, "argv must be typed and shell-free")
    if launch.get("environment_policy") != "allowlist":
        add(out, "route_environment_not_allowlisted", where, "child environment must be allowlisted")
    if not isinstance(launch.get("program"), str) or not isinstance(launch.get("argv"), list):
        add(out, "route_launch_shape_invalid", where, "program and argv are required")
    model = route.get("model_selection", {})
    if not isinstance(model, dict) or model.get("fixed_model_id") is not None or model.get("per_attempt_receipt") is not True:
        add(out, "route_fixed_model", where, "model must be discovered, selected, and receipted per attempt")
    events = route.get("event_contract", {})
    if events.get("durable_bridge_required") is not True or events.get("terminal_result_separate") is not True:
        add(out, "route_event_contract_invalid", where, "durable events and terminal result must remain separate")
    if events.get("coverage_status") not in {"unprobed", "partial", "documented_not_observed", "observed"}:
        add(out, "route_event_coverage_invalid", where, "invalid coverage status")
    children = route.get("child_agents", {})
    if children.get("descendant_closure_required") is not True:
        add(out, "route_descendant_closure_missing", where, "parent disposition requires descendant closure")
    if children.get("admission") not in {"disabled_until_probed", "explicit_work_item_only", "unavailable"}:
        add(out, "route_child_admission_invalid", where, "native child authority is too broad")
    if route.get("swarm") != SWARM:
        add(out, "route_swarm_contract_invalid", where, "swarm must remain an ELIOT-owned evidence pipeline")
    return out


def profile_errors(profile: Any, host: str, root: Path | None = None) -> list[Finding]:
    relative = PROFILE.format(host=host)
    out: list[Finding] = []
    if not isinstance(profile, dict):
        return [("profile_invalid", relative, "profile must be an object")]
    missing = TOP - set(profile)
    if missing:
        add(out, "profile_required_gap", relative, f"missing {sorted(missing)}")
    if profile.get("schema_version") != VERSION or profile.get("host_family") != host:
        add(out, "profile_identity_invalid", relative, "schema version or host family drifted")
    if profile.get("evidence_execution_status") != "NOT_EXECUTED":
        add(out, "profile_execution_overclaim", relative, "static work cannot claim runtime execution")
    if profile.get("skills") != SKILLS:
        add(out, "profile_skill_contract_invalid", relative, "lazy canonical Skill contract drifted")
    if profile.get("coordination") != COORDINATION:
        add(out, "profile_coordination_invalid", relative, "mailbox/Concilium ownership drifted")
    mcp = profile.get("mcp", {})
    if mcp.get("raw_store_access") is not False or mcp.get("tool_visibility") != "task_relative_lazy":
        add(out, "profile_mcp_boundary_invalid", relative, "MCP must remain task-relative and store-neutral")
    anchors = profile.get("architecture_anchors")
    if not isinstance(anchors, list) or not anchors or not all(isinstance(x, str) and x.startswith("ARCH-") for x in anchors):
        add(out, "profile_architecture_anchors_invalid", relative, "ARCH-* anchors are required")
    for key in ("probe_requirements", "known_gaps", "source_refs"):
        if not isinstance(profile.get(key), list) or not profile[key]:
            add(out, f"profile_{key}_missing", relative, f"{key} must be non-empty")
    for source in profile.get("source_refs", []):
        if not isinstance(source, str) or not source.startswith("https://"):
            add(out, "profile_source_invalid", relative, repr(source))

    surfaces = profile.get("host_surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        add(out, "profile_surfaces_missing", relative, "host surfaces must be non-empty")
    else:
        seen: set[str] = set()
        for index, surface in enumerate(surfaces):
            where = f"{relative}:host_surfaces[{index}]"
            if not isinstance(surface, dict):
                add(out, "surface_invalid", where, "surface must be an object")
                continue
            sid = surface.get("surface_id")
            if not isinstance(sid, str) or not sid or sid in seen:
                add(out, "surface_id_invalid", where, repr(sid))
            else:
                seen.add(sid)
            if surface.get("authority_ceiling") not in {"none", "observation_candidate", "pre_effect_gate_candidate"}:
                add(out, "surface_authority_invalid", where, "surface claims excess authority")
            declared = surface.get("path")
            if root and surface.get("status") == "implemented_unverified" and (not isinstance(declared, str) or not (root / declared).exists()):
                add(out, "surface_path_absent", where, repr(declared))

    routes = profile.get("execution_routes")
    if not isinstance(routes, list) or not routes:
        add(out, "profile_routes_missing", relative, "execution routes must be non-empty")
        return out
    ids = {r.get("route_id") for r in routes if isinstance(r, dict)}
    if ids != ROUTE_IDS[host]:
        add(out, "profile_route_set_invalid", relative, f"expected {sorted(ROUTE_IDS[host])}, got {sorted(map(str, ids))}")
    if sum(isinstance(r, dict) and r.get("role") == "primary_candidate" for r in routes) != 1:
        add(out, "profile_primary_count_invalid", relative, "exactly one primary candidate is required")
    for index, route in enumerate(routes):
        out.extend(route_errors(route, f"{relative}:execution_routes[{index}]"))

    if host == "codex":
        route = routes[0]
        if route.get("transport") != "stdio_jsonl" or route.get("launch", {}).get("argv", [])[:1] != ["app-server"]:
            add(out, "codex_app_server_missing", relative, "PRIMARY-1 must be App Server stdio")
    elif host == "opencode":
        route = routes[0]
        if "http" not in route.get("transport", "") or route.get("launch", {}).get("argv", [])[:1] != ["serve"]:
            add(out, "opencode_server_missing", relative, "PRIMARY-2 must be local HTTP/SSE")
    elif host == "claude":
        local = next((r for r in routes if r.get("route_id") == "claude.agent-sdk.local-sidecar"), {})
        remote = next((r for r in routes if r.get("route_id") == "claude.managed-agents.remote"), {})
        if local.get("launch", {}).get("program") != "eliot-claude-sidecar" or remote.get("status") != "deferred":
            add(out, "claude_route_separation_invalid", relative, "local SDK and remote Managed Agents must be distinct")
    else:
        primary = next((r for r in routes if r.get("role") == "primary_candidate"), {})
        fallback = next((r for r in routes if r.get("role") == "fallback"), {})
        if primary.get("launch", {}).get("program") != "antigravity" or fallback.get("launch", {}).get("program") != "agy":
            add(out, "antigravity_route_separation_invalid", relative, "stream and read-only fallback must be distinct")
    return out
