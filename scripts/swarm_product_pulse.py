#!/usr/bin/env python3
"""Validate a deterministic, provider-free ELIOT swarm Product Pulse.

The pulse proves control-plane shape only. It does not execute a provider or
promote a route.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

CONTRACT_PATH = Path("integrations/agent-runtimes/swarm-product-pulse.contract.json")
SCENARIO_PATH = Path("integrations/agent-runtimes/swarm-product-pulse.scenario.json")
CONTRACT_VERSION = "eliot.swarm-product-pulse-contract.v1"
SCENARIO_VERSION = "eliot.swarm-product-pulse-scenario.v1"
RECEIPT_VERSION = "eliot.swarm-product-pulse-receipt.v1"


class SwarmPulseError(RuntimeError):
    """A stable control-plane validation failure."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SwarmPulseError(f"{label}: unreadable JSON") from error
    if not isinstance(value, dict):
        raise SwarmPulseError(f"{label}: JSON root must be an object")
    return value


def _nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SwarmPulseError(f"{field}: nonblank string required")
    return value.strip()


def _safe_repo_path(root: Path, raw: Any, field: str) -> Path:
    value = _nonblank(raw, field)
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise SwarmPulseError(f"{field}: unsafe repository path")
    candidate = root.joinpath(*relative.parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise SwarmPulseError(f"{field}: route profile is missing or unsafe")
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise SwarmPulseError(f"{field}: path escaped repository root") from error
    return candidate


def _reject_forbidden_keys(value: Any, fragments: list[str], location: str = "$") -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).lower().replace("-", "_")
            if any(fragment in key for fragment in fragments):
                raise SwarmPulseError(f"{location}: forbidden payload key")
            _reject_forbidden_keys(child, fragments, f"{location}.{raw_key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_keys(child, fragments, f"{location}[{index}]")


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != CONTRACT_VERSION:
        raise SwarmPulseError("swarm pulse contract schema mismatch")
    if contract.get("scenario_schema") != SCENARIO_VERSION or contract.get("receipt_schema") != RECEIPT_VERSION:
        raise SwarmPulseError("swarm pulse schema family mismatch")
    if contract.get("required_hosts") != ["codex", "opencode", "claude", "antigravity"]:
        raise SwarmPulseError("swarm host set/order drifted")
    expected = {
        "control_plane": "eliot.coordinate",
        "message_transport": "durable_mailbox",
        "meeting_form": "concilium_over_sealed_evidence",
        "direct_group_chat": False,
        "worker_voting": False,
        "native_subagents": False,
        "provider_execution_allowed": False,
        "worker_result_authority": "candidate_only",
        "decision_owner": "task_controller_or_human",
        "promotion_disposition": "simulated_no_promotion",
        "eligible_for_route_promotion": False,
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise SwarmPulseError(f"swarm contract boundary drifted: {key}")
    limits = contract.get("limits")
    if not isinstance(limits, dict):
        raise SwarmPulseError("swarm limits are missing")
    for key in (
        "max_work_items",
        "max_mailbox_messages",
        "max_context_packet_bytes",
        "max_result_packet_bytes",
        "max_claims_per_result",
        "max_evidence_refs_per_result",
        "max_concilium_tests",
    ):
        if not isinstance(limits.get(key), int) or limits[key] <= 0:
            raise SwarmPulseError(f"swarm limit is invalid: {key}")
    for field in ("context_packet_allowed_fields", "result_packet_allowed_fields", "forbidden_payload_key_fragments"):
        value = contract.get(field)
        if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
            raise SwarmPulseError(f"swarm contract list is invalid: {field}")


def _validate_route_profile(profile: dict[str, Any], host: str) -> dict[str, Any]:
    if profile.get("schema_version") != "eliot.agent-route-profile.v1" or profile.get("host_family") != host:
        raise SwarmPulseError(f"{host}: route profile identity mismatch")
    routes = profile.get("execution_routes")
    if not isinstance(routes, list):
        raise SwarmPulseError(f"{host}: route list missing")
    primary = [route for route in routes if isinstance(route, dict) and route.get("role") == "primary_candidate"]
    if len(primary) != 1:
        raise SwarmPulseError(f"{host}: exactly one primary candidate required")
    route = primary[0]
    launch = route.get("launch", {})
    if launch.get("argv_construction") != "typed_no_shell" or launch.get("shell") is not False:
        raise SwarmPulseError(f"{host}: route launch is not typed/shell-free")
    if launch.get("environment_policy") != "allowlist":
        raise SwarmPulseError(f"{host}: route environment is not allowlisted")
    model = route.get("model_selection", {})
    if model.get("fixed_model_id") is not None or model.get("per_attempt_receipt") is not True:
        raise SwarmPulseError(f"{host}: model selection contract drifted")
    events = route.get("event_contract", {})
    if events.get("durable_bridge_required") is not True or events.get("terminal_result_separate") is not True:
        raise SwarmPulseError(f"{host}: durable event/terminal separation missing")
    children = route.get("child_agents", {})
    if children.get("descendant_closure_required") is not True:
        raise SwarmPulseError(f"{host}: descendant closure is not required")
    swarm = route.get("swarm", {})
    if swarm.get("control_plane") != "eliot.coordinate" or swarm.get("durable_mailbox") is not True:
        raise SwarmPulseError(f"{host}: ELIOT swarm/mailbox ownership drifted")
    if swarm.get("direct_group_chat") is not False or swarm.get("recursive_launch_default") != "disabled":
        raise SwarmPulseError(f"{host}: direct group chat or recursive launch enabled")
    skills = profile.get("skills", {})
    if skills.get("canonical_source") != "integrations/agent-skills" or skills.get("delivery") != "lazy":
        raise SwarmPulseError(f"{host}: lazy canonical Skills drifted")
    mcp = profile.get("mcp", {})
    if mcp.get("raw_store_access") is not False or mcp.get("tool_visibility") != "task_relative_lazy":
        raise SwarmPulseError(f"{host}: task-relative MCP boundary drifted")
    return route


def _bounded_packet(packet: Any, allowed: set[str], maximum: int, field: str) -> dict[str, Any]:
    if not isinstance(packet, dict) or not packet:
        raise SwarmPulseError(f"{field}: packet is missing")
    unknown = set(packet) - allowed
    if unknown:
        raise SwarmPulseError(f"{field}: packet contains undeclared fields")
    if len(canonical_json_bytes(packet)) > maximum:
        raise SwarmPulseError(f"{field}: packet exceeds bound")
    return packet


def run_swarm_pulse(root: Path, contract: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    validate_contract(contract)
    if scenario.get("schema_version") != SCENARIO_VERSION:
        raise SwarmPulseError("swarm scenario schema mismatch")
    _reject_forbidden_keys(scenario, contract["forbidden_payload_key_fragments"])
    task = scenario.get("task")
    if not isinstance(task, dict):
        raise SwarmPulseError("task identity is missing")
    for field in ("task_id", "work_scope_id", "controller_id"):
        _nonblank(task.get(field), f"task.{field}")

    work_items = scenario.get("work_items")
    if not isinstance(work_items, list) or len(work_items) != 4:
        raise SwarmPulseError("scenario must contain exactly four WorkItems")
    if len(work_items) > contract["limits"]["max_work_items"]:
        raise SwarmPulseError("WorkItem limit exceeded")
    hosts: set[str] = set()
    work_ids: set[str] = set()
    attempt_ids: set[str] = set()
    work_by_attempt: dict[str, dict[str, Any]] = {}
    context_hashes: dict[str, str] = {}
    route_hashes: dict[str, str] = {}
    expected_results: dict[str, str] = {}
    expected_cancellations: dict[str, str] = {}

    for item in work_items:
        if not isinstance(item, dict):
            raise SwarmPulseError("WorkItem is invalid")
        work_id = _nonblank(item.get("work_item_id"), "work_item_id")
        attempt_id = _nonblank(item.get("attempt_id"), "attempt_id")
        host = _nonblank(item.get("host"), "host")
        if work_id in work_ids or attempt_id in attempt_ids or host in hosts:
            raise SwarmPulseError("duplicate WorkItem, attempt, or host identity")
        work_ids.add(work_id)
        attempt_ids.add(attempt_id)
        hosts.add(host)
        work_by_attempt[attempt_id] = item
        if item.get("selected_model_id") is not None:
            raise SwarmPulseError("simulated pulse may not claim a selected current-account model")
        _nonblank(item.get("model_selection_receipt_ref"), "model_selection_receipt_ref")
        if item.get("provider_execution") is not False:
            raise SwarmPulseError("simulated pulse may not execute a provider")
        if item.get("native_subagents") is not False:
            raise SwarmPulseError("native subagents are disabled in the baseline pulse")
        profile_path = _safe_repo_path(root, item.get("route_profile"), "route_profile")
        profile = load_json(profile_path, f"{host} route profile")
        _validate_route_profile(profile, host)
        route_hashes[host] = sha256_json(profile)
        packet = _bounded_packet(
            item.get("context_packet"),
            set(contract["context_packet_allowed_fields"]),
            contract["limits"]["max_context_packet_bytes"],
            f"{work_id}.context_packet",
        )
        context_hashes[work_id] = sha256_json(packet)
        terminal = item.get("terminal")
        if terminal == "succeeded":
            result_ref = _nonblank(item.get("result_ref"), "result_ref")
            if item.get("cancellation_ref") is not None:
                raise SwarmPulseError("successful WorkItem also carries cancellation")
            expected_results[result_ref] = attempt_id
        elif terminal == "cancelled":
            cancellation_ref = _nonblank(item.get("cancellation_ref"), "cancellation_ref")
            if item.get("result_ref") is not None:
                raise SwarmPulseError("cancelled WorkItem also carries result")
            expected_cancellations[cancellation_ref] = attempt_id
        else:
            raise SwarmPulseError("unsupported WorkItem terminal disposition")

    if hosts != set(contract["required_hosts"]):
        raise SwarmPulseError("scenario host coverage is incomplete")

    results = scenario.get("sealed_results")
    if not isinstance(results, list) or len(results) != len(expected_results):
        raise SwarmPulseError("sealed result denominator mismatch")
    result_hashes: dict[str, str] = {}
    seen_results: set[str] = set()
    for result in results:
        if not isinstance(result, dict):
            raise SwarmPulseError("sealed result is invalid")
        result_ref = _nonblank(result.get("result_ref"), "result_ref")
        attempt_id = _nonblank(result.get("attempt_id"), "result.attempt_id")
        if result_ref in seen_results or expected_results.get(result_ref) != attempt_id:
            raise SwarmPulseError("sealed result identity mismatch")
        seen_results.add(result_ref)
        if result.get("candidate_only") is not True or result.get("authority") != "none":
            raise SwarmPulseError("worker result exceeded candidate-only authority")
        packet = _bounded_packet(
            result.get("packet"),
            set(contract["result_packet_allowed_fields"]),
            contract["limits"]["max_result_packet_bytes"],
            f"{result_ref}.packet",
        )
        claims = packet.get("claims", [])
        evidence_refs = packet.get("evidence_refs", [])
        if not isinstance(claims, list) or len(claims) > contract["limits"]["max_claims_per_result"]:
            raise SwarmPulseError("result claim bound exceeded")
        if not isinstance(evidence_refs, list) or len(evidence_refs) > contract["limits"]["max_evidence_refs_per_result"]:
            raise SwarmPulseError("result evidence bound exceeded")
        result_hashes[result_ref] = sha256_json(result)
    if seen_results != set(expected_results):
        raise SwarmPulseError("sealed result coverage is incomplete")

    cancellations = scenario.get("cancellation_receipts")
    if not isinstance(cancellations, list) or len(cancellations) != len(expected_cancellations):
        raise SwarmPulseError("cancellation receipt denominator mismatch")
    cancellation_hashes: dict[str, str] = {}
    seen_cancellations: set[str] = set()
    for receipt in cancellations:
        if not isinstance(receipt, dict):
            raise SwarmPulseError("cancellation receipt is invalid")
        reference = _nonblank(receipt.get("cancellation_ref"), "cancellation_ref")
        attempt_id = _nonblank(receipt.get("attempt_id"), "cancellation.attempt_id")
        if reference in seen_cancellations or expected_cancellations.get(reference) != attempt_id:
            raise SwarmPulseError("cancellation identity mismatch")
        seen_cancellations.add(reference)
        if receipt.get("outcome") != "cancelled_confirmed":
            raise SwarmPulseError("cancellation outcome is not reconciled")
        if receipt.get("process_tree_closed") is not True or receipt.get("descendants_closed") is not True:
            raise SwarmPulseError("cancellation lacks process/descendant closure")
        if receipt.get("unknown_live_descendants") is not False:
            raise SwarmPulseError("cancellation retains unknown live descendants")
        _nonblank(receipt.get("terminal_readback"), "terminal_readback")
        cancellation_hashes[reference] = sha256_json(receipt)
    if seen_cancellations != set(expected_cancellations):
        raise SwarmPulseError("cancellation coverage is incomplete")

    mailbox = scenario.get("mailbox")
    if not isinstance(mailbox, list) or len(mailbox) > contract["limits"]["max_mailbox_messages"]:
        raise SwarmPulseError("mailbox is invalid or exceeds bound")
    message_ids: set[str] = set()
    context_deliveries: set[str] = set()
    terminal_deliveries: set[str] = set()
    for message in mailbox:
        if not isinstance(message, dict):
            raise SwarmPulseError("mailbox message is invalid")
        message_id = _nonblank(message.get("message_id"), "message_id")
        source = _nonblank(message.get("from"), "mail.from")
        target = _nonblank(message.get("to"), "mail.to")
        kind = _nonblank(message.get("kind"), "mail.kind")
        reference = _nonblank(message.get("reference"), "mail.reference")
        if message_id in message_ids:
            raise SwarmPulseError("duplicate mailbox message identity")
        message_ids.add(message_id)
        source_is_attempt = source in attempt_ids
        target_is_attempt = target in attempt_ids
        if source_is_attempt and target_is_attempt:
            raise SwarmPulseError("direct worker-to-worker group chat is forbidden")
        if source == "task_controller" and target_is_attempt and kind == "context_packet_ref":
            expected = f"context:{work_by_attempt[target]['work_item_id']}"
            if reference != expected:
                raise SwarmPulseError("mailbox context reference mismatch")
            context_deliveries.add(target)
        elif source_is_attempt and target == "task_controller" and kind == "sealed_result_ref":
            if expected_results.get(reference) != source:
                raise SwarmPulseError("mailbox result reference mismatch")
            terminal_deliveries.add(source)
        elif source_is_attempt and target == "task_controller" and kind == "cancellation_receipt_ref":
            if expected_cancellations.get(reference) != source:
                raise SwarmPulseError("mailbox cancellation reference mismatch")
            terminal_deliveries.add(source)
        else:
            raise SwarmPulseError("mailbox message violates controller/worker topology")
    if context_deliveries != attempt_ids or terminal_deliveries != attempt_ids:
        raise SwarmPulseError("mailbox delivery coverage is incomplete")

    concilium = scenario.get("concilium")
    if not isinstance(concilium, dict) or concilium.get("form") != contract["meeting_form"]:
        raise SwarmPulseError("Concilium form is invalid")
    expected_evidence = set(expected_results) | set(expected_cancellations)
    evidence_refs = concilium.get("evidence_refs")
    if not isinstance(evidence_refs, list) or set(evidence_refs) != expected_evidence or len(evidence_refs) != len(expected_evidence):
        raise SwarmPulseError("Concilium evidence denominator mismatch")
    for field in ("rival_models", "objections", "discriminative_tests", "preserved_dissent"):
        value = concilium.get(field)
        if not isinstance(value, list) or not value:
            raise SwarmPulseError(f"Concilium field is missing: {field}")
    if len(concilium["discriminative_tests"]) > contract["limits"]["max_concilium_tests"]:
        raise SwarmPulseError("Concilium test bound exceeded")
    _nonblank(concilium.get("synthesis_ref"), "concilium.synthesis_ref")
    if concilium.get("result_authority") != "candidate_only":
        raise SwarmPulseError("Concilium result exceeded candidate authority")

    decision = scenario.get("decision")
    if not isinstance(decision, dict):
        raise SwarmPulseError("controller decision is missing")
    if decision.get("owner") != contract["decision_owner"]:
        raise SwarmPulseError("worker or synthesis layer claimed decision ownership")
    if decision.get("disposition") != contract["promotion_disposition"]:
        raise SwarmPulseError("simulated pulse attempted an unsupported disposition")
    if decision.get("eligible_for_route_promotion") is not False:
        raise SwarmPulseError("simulated pulse cannot promote a route")

    basis = {
        "contract_sha256": sha256_json(contract),
        "scenario_sha256": sha256_json(scenario),
        "route_profile_sha256": dict(sorted(route_hashes.items())),
        "context_packet_sha256": dict(sorted(context_hashes.items())),
        "result_sha256": dict(sorted(result_hashes.items())),
        "cancellation_sha256": dict(sorted(cancellation_hashes.items())),
    }
    return {
        "schema_version": RECEIPT_VERSION,
        "pulse_id": f"sha256:{sha256_json(basis)}",
        **basis,
        "hosts": sorted(hosts),
        "work_items": len(work_items),
        "agent_attempts": len(attempt_ids),
        "sealed_results": len(results),
        "cancellations": len(cancellations),
        "mailbox_messages": len(mailbox),
        "provider_executions": 0,
        "selected_model_ids": 0,
        "native_subagents": False,
        "direct_group_chat": False,
        "worker_voting": False,
        "decision_owner": "task_controller_or_human",
        "decision_disposition": "simulated_no_promotion",
        "eligible_for_route_promotion": False,
        "proof_ceiling": "DETERMINISTIC_CONTROL_PLANE_SHAPE_ONLY",
    }
