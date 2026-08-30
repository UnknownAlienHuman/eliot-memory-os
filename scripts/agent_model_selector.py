#!/usr/bin/env python3
"""Deterministic, evidence-bound model selection for ELIOT AgentAttempts.

The selector consumes route catalogue receipts. It does not probe providers,
start a model, infer capabilities from names, or grant dispatch authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY_PATH = Path("integrations/agent-runtimes/model-selection.policy.json")
FIXTURE_PATH = Path("integrations/agent-runtimes/model-selection.fixture.json")
POLICY_VERSION = "eliot.agent-model-selection-policy.v1"
CATALOGUE_VERSION = "eliot.route-catalogue-set.v1"
RECEIPT_VERSION = "eliot.agent-model-selection-receipt.v1"
ROLE_ORDER = ("primary", "cheap_worker", "challenger", "verifier")
EVIDENCE_LEVELS = {
    "unknown": 0,
    "declared": 1,
    "observed": 2,
    "executed": 3,
    "independently_verified": 4,
}
FORBIDDEN_INPUT_KEY_FRAGMENTS = (
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
    "plugin_path",
    "command_line",
)


class SelectionError(RuntimeError):
    """A stable selector input/policy failure without protected payloads."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SelectionError(f"{label}: unreadable JSON") from error
    if not isinstance(value, dict):
        raise SelectionError(f"{label}: JSON root must be an object")
    return value


def reject_protected_inputs(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key).lower().replace("-", "_")
            if any(fragment in key for fragment in FORBIDDEN_INPUT_KEY_FRAGMENTS):
                raise SelectionError(f"{location}: protected selector input key is forbidden")
            reject_protected_inputs(child, f"{location}.{raw_key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_protected_inputs(child, f"{location}[{index}]")


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema_version") != POLICY_VERSION:
        raise SelectionError("model-selection policy schema mismatch")
    if policy.get("catalogue_schema") != CATALOGUE_VERSION:
        raise SelectionError("model-selection catalogue schema mismatch")
    if policy.get("receipt_schema") != RECEIPT_VERSION:
        raise SelectionError("model-selection receipt schema mismatch")
    if policy.get("fixed_model_id") is not None:
        raise SelectionError("fixed universal model IDs are forbidden")
    if policy.get("provider_execution_allowed") is not False:
        raise SelectionError("selector may not execute providers")
    if policy.get("dispatch_authority") is not False:
        raise SelectionError("selector may not grant dispatch authority")
    if policy.get("authority_ceiling") != "candidate_route_selection_only":
        raise SelectionError("selector authority ceiling drifted")
    allowed_hosts = policy.get("allowed_hosts")
    if allowed_hosts != ["codex", "opencode", "claude", "antigravity"]:
        raise SelectionError("selector host set drifted")
    minimum = policy.get("minimum_capability_evidence")
    if minimum not in EVIDENCE_LEVELS or EVIDENCE_LEVELS[minimum] < EVIDENCE_LEVELS["observed"]:
        raise SelectionError("minimum capability evidence must be observed or stronger")
    roles = policy.get("roles")
    if not isinstance(roles, dict) or tuple(roles) != ROLE_ORDER:
        raise SelectionError("selector role order/set drifted")
    for role, config in roles.items():
        if not isinstance(config, dict):
            raise SelectionError(f"{role}: role configuration is invalid")
        capabilities = config.get("required_capabilities")
        if not isinstance(capabilities, list) or not capabilities or not all(isinstance(item, str) and item for item in capabilities):
            raise SelectionError(f"{role}: required capability set is invalid")
        if not isinstance(config.get("minimum_context_tokens"), int) or config["minimum_context_tokens"] <= 0:
            raise SelectionError(f"{role}: context requirement is invalid")
        for field in ("different_host_from", "different_family_from"):
            references = config.get(field)
            if not isinstance(references, list) or any(reference not in ROLE_ORDER for reference in references):
                raise SelectionError(f"{role}: diversity reference is invalid")
    ranking = policy.get("ranking")
    if not isinstance(ranking, dict):
        raise SelectionError("ranking policy is missing")
    for field in (
        "route_admitted",
        "health_ready",
        "health_degraded",
        "quota_available",
        "quota_limited",
        "capability_evidence_unit",
        "context_headroom_unit_tokens",
        "context_headroom_unit_score",
        "context_headroom_max_score",
    ):
        if not isinstance(ranking.get(field), int):
            raise SelectionError(f"ranking field {field} is invalid")


@dataclass(frozen=True)
class Candidate:
    host: str
    route_id: str
    route_fingerprint: str
    account_scope_hash: str
    catalogue_observed_at: str
    admission_status: str
    health: str
    quota_status: str
    model_id: str
    model_family: str
    availability: str
    context_window_tokens: int
    cost_class: str
    latency_class: str
    capabilities: dict[str, dict[str, Any]]

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.host, self.route_id, self.model_id


def _nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SelectionError(f"{field}: nonblank string required")
    return value.strip()


def _parse_catalogue(catalogue: dict[str, Any], policy: dict[str, Any]) -> list[Candidate]:
    reject_protected_inputs(catalogue)
    if catalogue.get("schema_version") != CATALOGUE_VERSION:
        raise SelectionError("route catalogue schema mismatch")
    routes = catalogue.get("routes")
    if not isinstance(routes, list) or not routes:
        raise SelectionError("route catalogue is empty")
    allowed_hosts = set(policy["allowed_hosts"])
    primary_count = {host: 0 for host in allowed_hosts}
    seen_route_ids: set[tuple[str, str]] = set()
    seen_models: set[tuple[str, str, str]] = set()
    candidates: list[Candidate] = []
    for route in routes:
        if not isinstance(route, dict):
            raise SelectionError("route catalogue entry is invalid")
        host = _nonblank(route.get("host"), "host")
        if host not in allowed_hosts:
            raise SelectionError("route catalogue contains unsupported host")
        route_id = _nonblank(route.get("route_id"), "route_id")
        if (host, route_id) in seen_route_ids:
            raise SelectionError("duplicate route identity")
        seen_route_ids.add((host, route_id))
        if route.get("route_role") == "primary_candidate":
            primary_count[host] += 1
        route_fingerprint = _nonblank(route.get("route_fingerprint"), "route_fingerprint")
        account_scope_hash = _nonblank(route.get("account_scope_hash"), "account_scope_hash")
        observed_at = _nonblank(route.get("catalogue_observed_at"), "catalogue_observed_at")
        admission = _nonblank(route.get("admission_status"), "admission_status")
        health = _nonblank(route.get("health"), "health")
        quota = route.get("quota")
        if not isinstance(quota, dict):
            raise SelectionError("route quota receipt is missing")
        quota_status = _nonblank(quota.get("status"), "quota.status")
        models = route.get("models")
        if not isinstance(models, list):
            raise SelectionError("route model catalogue is invalid")
        for model in models:
            if not isinstance(model, dict):
                raise SelectionError("model catalogue entry is invalid")
            model_id = _nonblank(model.get("model_id"), "model_id")
            model_family = _nonblank(model.get("model_family"), "model_family")
            identity = (host, route_id, model_id)
            if identity in seen_models:
                raise SelectionError("duplicate model identity")
            seen_models.add(identity)
            context = model.get("context_window_tokens")
            if not isinstance(context, int) or context <= 0:
                raise SelectionError("model context window is invalid")
            capabilities = model.get("capabilities")
            if not isinstance(capabilities, dict):
                raise SelectionError("model capability evidence is missing")
            normalized_capabilities: dict[str, dict[str, Any]] = {}
            for capability, evidence in capabilities.items():
                if not isinstance(capability, str) or not capability or not isinstance(evidence, dict):
                    raise SelectionError("model capability evidence is invalid")
                support = evidence.get("support")
                level = evidence.get("evidence_level")
                if not isinstance(support, bool) or level not in EVIDENCE_LEVELS:
                    raise SelectionError("model capability evidence is invalid")
                normalized_capabilities[capability] = {
                    "support": support,
                    "evidence_level": level,
                }
            candidates.append(
                Candidate(
                    host=host,
                    route_id=route_id,
                    route_fingerprint=route_fingerprint,
                    account_scope_hash=account_scope_hash,
                    catalogue_observed_at=observed_at,
                    admission_status=admission,
                    health=health,
                    quota_status=quota_status,
                    model_id=model_id,
                    model_family=model_family,
                    availability=_nonblank(model.get("availability"), "availability"),
                    context_window_tokens=context,
                    cost_class=_nonblank(model.get("cost_class"), "cost_class"),
                    latency_class=_nonblank(model.get("latency_class"), "latency_class"),
                    capabilities=normalized_capabilities,
                )
            )
    if any(primary_count[host] != 1 for host in allowed_hosts):
        raise SelectionError("exactly one primary route candidate per host is required")
    return candidates


def _basic_rejections(candidate: Candidate, role: str, config: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if candidate.admission_status not in policy["dispatchable_route_admission"]:
        reasons.append("ROUTE_NOT_ADMITTED")
    if candidate.health not in policy["dispatchable_health"]:
        reasons.append("ROUTE_HEALTH_UNAVAILABLE")
    if candidate.quota_status not in policy["dispatchable_quota"]:
        reasons.append("QUOTA_NOT_DISPATCHABLE")
    if candidate.availability not in {"available", "degraded"}:
        reasons.append("MODEL_UNAVAILABLE")
    if candidate.context_window_tokens < config["minimum_context_tokens"]:
        reasons.append("CONTEXT_WINDOW_TOO_SMALL")
    minimum_evidence = EVIDENCE_LEVELS[policy["minimum_capability_evidence"]]
    for capability in config["required_capabilities"]:
        evidence = candidate.capabilities.get(capability)
        if evidence is None or evidence.get("support") is not True:
            reasons.append(f"CAPABILITY_UNSUPPORTED:{capability}")
            continue
        level = EVIDENCE_LEVELS.get(str(evidence.get("evidence_level")), 0)
        if level < minimum_evidence:
            reasons.append(f"CAPABILITY_EVIDENCE_TOO_WEAK:{capability}")
    return sorted(set(reasons))


def _score(candidate: Candidate, config: dict[str, Any], policy: dict[str, Any]) -> tuple[int, dict[str, int]]:
    ranking = policy["ranking"]
    components: dict[str, int] = {
        "route": ranking["route_admitted"],
        "health": ranking["health_ready"] if candidate.health == "ready" else ranking["health_degraded"],
        "quota": ranking["quota_available"] if candidate.quota_status == "available" else ranking["quota_limited"],
    }
    evidence_units = sum(
        EVIDENCE_LEVELS[candidate.capabilities[capability]["evidence_level"]]
        for capability in config["required_capabilities"]
    )
    components["capability_evidence"] = evidence_units * ranking["capability_evidence_unit"]
    headroom = max(0, candidate.context_window_tokens - config["minimum_context_tokens"])
    headroom_units = headroom // ranking["context_headroom_unit_tokens"]
    components["context_headroom"] = min(
        ranking["context_headroom_max_score"],
        headroom_units * ranking["context_headroom_unit_score"],
    )
    components["cost"] = ranking["cost"].get(candidate.cost_class, ranking["cost"]["unknown"]) if config.get("prefer_cost") else 0
    components["latency"] = ranking["latency"].get(candidate.latency_class, ranking["latency"]["unknown"]) if config.get("prefer_latency") else 0
    return sum(components.values()), components


def _diversity_rejections(candidate: Candidate, config: dict[str, Any], selected: dict[str, Candidate]) -> list[str]:
    reasons: list[str] = []
    for role in config["different_host_from"]:
        previous = selected.get(role)
        if previous is not None and previous.host == candidate.host:
            reasons.append(f"HOST_NOT_DIVERSE_FROM:{role}")
    for role in config["different_family_from"]:
        previous = selected.get(role)
        if previous is not None and previous.model_family == candidate.model_family:
            reasons.append(f"FAMILY_NOT_DIVERSE_FROM:{role}")
    return sorted(reasons)


def _candidate_record(candidate: Candidate, score: int, components: dict[str, int]) -> dict[str, Any]:
    return {
        "host": candidate.host,
        "route_id": candidate.route_id,
        "route_fingerprint": candidate.route_fingerprint,
        "account_scope_hash": candidate.account_scope_hash,
        "catalogue_observed_at": candidate.catalogue_observed_at,
        "model_id": candidate.model_id,
        "model_family": candidate.model_family,
        "score": score,
        "score_components": components,
    }


def select_models(policy: dict[str, Any], catalogue: dict[str, Any]) -> dict[str, Any]:
    validate_policy(policy)
    candidates = _parse_catalogue(catalogue, policy)
    selected_candidates: dict[str, Candidate] = {}
    selections: list[dict[str, Any]] = []
    overall_diversity = "satisfied"

    for role in ROLE_ORDER:
        config = policy["roles"][role]
        basic: list[tuple[Candidate, int, dict[str, int]]] = []
        rejected: list[dict[str, Any]] = []
        for candidate in candidates:
            reasons = _basic_rejections(candidate, role, config, policy)
            if reasons:
                rejected.append({
                    "host": candidate.host,
                    "route_id": candidate.route_id,
                    "model_id": candidate.model_id,
                    "reason_codes": reasons,
                })
                continue
            score, components = _score(candidate, config, policy)
            basic.append((candidate, score, components))
        basic.sort(key=lambda item: (-item[1], item[0].host, item[0].route_id, item[0].model_id))

        strict: list[tuple[Candidate, int, dict[str, int]]] = []
        diversity_rejected: list[dict[str, Any]] = []
        for candidate, score, components in basic:
            reasons = _diversity_rejections(candidate, config, selected_candidates)
            if reasons:
                diversity_rejected.append({
                    "host": candidate.host,
                    "route_id": candidate.route_id,
                    "model_id": candidate.model_id,
                    "reason_codes": reasons,
                })
            else:
                strict.append((candidate, score, components))

        role_diversity = "not_applicable" if not config["different_host_from"] and not config["different_family_from"] else "satisfied"
        pool = strict
        if not pool and basic:
            pool = basic
            role_diversity = "degraded"
            overall_diversity = "degraded"
        if not pool:
            selections.append({
                "role": role,
                "status": "unavailable",
                "diversity_status": role_diversity,
                "selected": None,
                "alternatives": [],
                "rejections": sorted(rejected + diversity_rejected, key=lambda item: (item["host"], item["route_id"], item["model_id"])),
            })
            continue

        chosen, chosen_score, chosen_components = pool[0]
        selected_candidates[role] = chosen
        alternatives = [_candidate_record(candidate, score, components) for candidate, score, components in pool[1:]]
        selections.append({
            "role": role,
            "status": "selected",
            "diversity_status": role_diversity,
            "selected": _candidate_record(chosen, chosen_score, chosen_components),
            "alternatives": alternatives,
            "rejections": sorted(rejected + diversity_rejected, key=lambda item: (item["host"], item["route_id"], item["model_id"])),
        })

    selection_basis = {
        "policy_sha256": sha256_json(policy),
        "catalogue_sha256": sha256_json(catalogue),
        "selections": selections,
    }
    receipt = {
        "schema_version": RECEIPT_VERSION,
        "selection_id": f"sha256:{sha256_json(selection_basis)}",
        "policy_sha256": selection_basis["policy_sha256"],
        "catalogue_sha256": selection_basis["catalogue_sha256"],
        "catalogue_set_id": catalogue.get("catalogue_set_id"),
        "selections": selections,
        "diversity_status": overall_diversity,
        "provider_executions": 0,
        "dispatch_authority": False,
        "authority": "candidate_route_selection_only",
        "proof_ceiling": "DETERMINISTIC_SELECTION_OVER_SUPPLIED_RECEIPTS_ONLY",
    }
    return receipt


def selection_for_role(receipt: dict[str, Any], role: str) -> dict[str, Any] | None:
    for item in receipt.get("selections", []):
        if isinstance(item, dict) and item.get("role") == role:
            selected = item.get("selected")
            return selected if isinstance(selected, dict) else None
    return None


def clone_without_protected_payload(value: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(value)
