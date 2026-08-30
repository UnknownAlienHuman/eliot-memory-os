#!/usr/bin/env python3
"""Deterministic, no-execution route/model selection for ELIOT AgentAttempts."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

POLICY_VERSION = "eliot.agent-model-selection-policy.v1"
INPUT_VERSION = "eliot.agent-model-selection-input.v1"
RECEIPT_VERSION = "eliot.agent-model-selection-receipt.v1"
HOSTS = {"codex", "opencode", "claude", "antigravity"}
ROUTE_HEALTH = {"unknown": 0, "degraded": 1, "healthy": 2}
FORBIDDEN_KEY_FRAGMENTS = (
    "api_key", "apikey", "authorization", "bearer", "cookie", "credential",
    "password", "private_key", "secret", "token",
)
MAX_CANDIDATES = 256
MAX_REJECTIONS = 512


class SelectionError(ValueError):
    """Stable selector input/policy failure."""


@dataclass(frozen=True)
class RolePolicy:
    role: str
    required_capabilities: tuple[str, ...]
    minimum_context_window: int
    maximum_cost_class: int
    maximum_latency_class: int
    diversity_from: tuple[str, ...]


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SelectionError(f"{field}: nonblank string required")
    if len(value) > 1024:
        raise SelectionError(f"{field}: value is too long")
    return value


def _require_int(value: Any, field: str, *, minimum: int = 0, maximum: int = 10_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SelectionError(f"{field}: integer in [{minimum}, {maximum}] required")
    return value


def reject_secret_bearing_shape(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            lowered = str(key).lower().replace("-", "_")
            if any(fragment in lowered for fragment in FORBIDDEN_KEY_FRAGMENTS):
                raise SelectionError(f"{path}.{key}: secret-bearing fields are forbidden")
            reject_secret_bearing_shape(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            reject_secret_bearing_shape(child, f"{path}[{index}]")


def parse_policy(raw: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, RolePolicy], dict[str, int]]:
    if raw.get("schema_version") != POLICY_VERSION:
        raise SelectionError("policy.schema_version: unsupported policy version")
    if "fixed_model_id" in raw or "default_model_id" in raw:
        raise SelectionError("policy: fixed/default model identity is forbidden")
    order = raw.get("evidence_order")
    if not isinstance(order, list) or len(order) < 2 or len(order) != len(set(order)):
        raise SelectionError("policy.evidence_order: unique nonempty list required")
    evidence_rank = {str(value): index for index, value in enumerate(order)}
    minimum = _require_text(raw.get("minimum_capability_evidence"), "policy.minimum_capability_evidence")
    if minimum not in evidence_rank:
        raise SelectionError("policy.minimum_capability_evidence: value is not in evidence_order")
    role_rows = raw.get("roles")
    if not isinstance(role_rows, list) or not role_rows:
        raise SelectionError("policy.roles: nonempty list required")
    roles: dict[str, RolePolicy] = {}
    for index, row in enumerate(role_rows):
        if not isinstance(row, Mapping):
            raise SelectionError(f"policy.roles[{index}]: object required")
        role = _require_text(row.get("role"), f"policy.roles[{index}].role")
        if role in roles:
            raise SelectionError(f"policy.roles[{index}].role: duplicate role")
        caps = row.get("required_capabilities")
        diversity = row.get("diversity_from")
        if not isinstance(caps, list) or not caps or len(caps) != len(set(caps)):
            raise SelectionError(f"policy.roles[{index}].required_capabilities: unique nonempty list required")
        if not isinstance(diversity, list) or len(diversity) != len(set(diversity)):
            raise SelectionError(f"policy.roles[{index}].diversity_from: unique list required")
        roles[role] = RolePolicy(
            role=role,
            required_capabilities=tuple(_require_text(v, f"policy.roles[{index}].required_capabilities") for v in caps),
            minimum_context_window=_require_int(row.get("minimum_context_window"), f"policy.roles[{index}].minimum_context_window"),
            maximum_cost_class=_require_int(row.get("maximum_cost_class"), f"policy.roles[{index}].maximum_cost_class", maximum=100),
            maximum_latency_class=_require_int(row.get("maximum_latency_class"), f"policy.roles[{index}].maximum_latency_class", maximum=100),
            diversity_from=tuple(_require_text(v, f"policy.roles[{index}].diversity_from") for v in diversity),
        )
    for role in roles.values():
        unknown = set(role.diversity_from) - set(roles)
        if unknown:
            raise SelectionError(f"policy role {role.role}: unknown diversity roles {sorted(unknown)}")
    for field in (
        "admitted_route_statuses", "current_catalogue_statuses",
        "dispatchable_availability", "dispatchable_quota_statuses", "diversity_dimensions",
    ):
        value = raw.get(field)
        if not isinstance(value, list) or not value or len(value) != len(set(value)):
            raise SelectionError(f"policy.{field}: unique nonempty list required")
    return dict(raw), roles, evidence_rank


def validate_candidate(candidate: Mapping[str, Any], index: int) -> dict[str, Any]:
    required_text = (
        "host", "route_id", "route_fingerprint", "account_scope", "catalogue_observed_at",
        "catalogue_status", "route_admission", "route_health", "provider_id", "model_id",
        "model_family", "availability", "quota_status",
    )
    normalized = dict(candidate)
    for field in required_text:
        normalized[field] = _require_text(candidate.get(field), f"candidates[{index}].{field}")
    if normalized["host"] not in HOSTS:
        raise SelectionError(f"candidates[{index}].host: unsupported host")
    if normalized["route_health"] not in ROUTE_HEALTH:
        raise SelectionError(f"candidates[{index}].route_health: unsupported value")
    for field, maximum in (("context_window", 100_000_000), ("cost_class", 100), ("latency_class", 100)):
        normalized[field] = _require_int(candidate.get(field), f"candidates[{index}].{field}", maximum=maximum)
    roles = candidate.get("role_eligibility")
    if not isinstance(roles, list) or not roles or len(roles) != len(set(roles)):
        raise SelectionError(f"candidates[{index}].role_eligibility: unique nonempty list required")
    normalized["role_eligibility"] = tuple(_require_text(v, f"candidates[{index}].role_eligibility") for v in roles)
    capabilities = candidate.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise SelectionError(f"candidates[{index}].capabilities: object required")
    normalized_caps: dict[str, dict[str, str]] = {}
    for name, evidence in capabilities.items():
        cap = _require_text(name, f"candidates[{index}].capabilities")
        if not isinstance(evidence, Mapping):
            raise SelectionError(f"candidates[{index}].capabilities.{cap}: object required")
        normalized_caps[cap] = {
            "status": _require_text(evidence.get("status"), f"candidates[{index}].capabilities.{cap}.status"),
            "evidence": _require_text(evidence.get("evidence"), f"candidates[{index}].capabilities.{cap}.evidence"),
            "receipt_ref": _require_text(evidence.get("receipt_ref"), f"candidates[{index}].capabilities.{cap}.receipt_ref"),
        }
    normalized["capabilities"] = normalized_caps
    return normalized


def candidate_key(candidate: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (candidate["host"], candidate["route_id"], candidate["provider_id"], candidate["model_id"])


def evaluate_candidate(
    candidate: Mapping[str, Any], role: RolePolicy, policy: Mapping[str, Any], evidence_rank: Mapping[str, int]
) -> tuple[list[str], tuple[Any, ...]]:
    reasons: list[str] = []
    if role.role not in candidate["role_eligibility"]:
        reasons.append("ROLE_NOT_RECEIPTED")
    if candidate["route_admission"] not in policy["admitted_route_statuses"]:
        reasons.append("ROUTE_NOT_ADMITTED")
    if candidate["catalogue_status"] not in policy["current_catalogue_statuses"]:
        reasons.append("CATALOGUE_NOT_CURRENT")
    if candidate["availability"] not in policy["dispatchable_availability"]:
        reasons.append("MODEL_UNAVAILABLE")
    if candidate["quota_status"] not in policy["dispatchable_quota_statuses"]:
        reasons.append("QUOTA_NOT_DISPATCHABLE")
    if candidate["context_window"] < role.minimum_context_window:
        reasons.append("CONTEXT_WINDOW_TOO_SMALL")
    if candidate["cost_class"] > role.maximum_cost_class:
        reasons.append("COST_CLASS_TOO_HIGH")
    if candidate["latency_class"] > role.maximum_latency_class:
        reasons.append("LATENCY_CLASS_TOO_HIGH")
    minimum_rank = evidence_rank[policy["minimum_capability_evidence"]]
    capability_ranks: list[int] = []
    for capability in role.required_capabilities:
        receipt = candidate["capabilities"].get(capability)
        if receipt is None or receipt["status"] != "supported":
            reasons.append(f"CAPABILITY_UNSUPPORTED:{capability}")
            continue
        rank = evidence_rank.get(receipt["evidence"], -1)
        if rank < minimum_rank:
            reasons.append(f"CAPABILITY_EVIDENCE_TOO_WEAK:{capability}")
        capability_ranks.append(rank)
    score = (
        ROUTE_HEALTH[candidate["route_health"]],
        min(capability_ranks, default=-1),
        candidate["context_window"],
        -candidate["cost_class"],
        -candidate["latency_class"],
        tuple(-ord(ch) for ch in "|".join(candidate_key(candidate))),
    )
    return sorted(set(reasons)), score


def diversity_gaps(candidate: Mapping[str, Any], role: RolePolicy, selected: Mapping[str, Mapping[str, Any]], dimensions: Sequence[str]) -> list[str]:
    gaps: list[str] = []
    for prior_role in role.diversity_from:
        prior = selected.get(prior_role)
        if prior is None:
            continue
        for dimension in dimensions:
            if candidate.get(dimension) == prior.get(dimension):
                gaps.append(f"{prior_role}:{dimension}")
    return sorted(set(gaps))


def select_models(policy_raw: Mapping[str, Any], input_raw: Mapping[str, Any]) -> dict[str, Any]:
    reject_secret_bearing_shape(policy_raw, "$.policy")
    reject_secret_bearing_shape(input_raw, "$.input")
    policy, roles, evidence_rank = parse_policy(policy_raw)
    if input_raw.get("schema_version") != INPUT_VERSION:
        raise SelectionError("input.schema_version: unsupported input version")
    selection_id = _require_text(input_raw.get("selection_id"), "input.selection_id")
    attempt_scope = _require_text(input_raw.get("attempt_scope"), "input.attempt_scope")
    requested = input_raw.get("requested_roles")
    if not isinstance(requested, list) or not requested or len(requested) != len(set(requested)):
        raise SelectionError("input.requested_roles: unique nonempty list required")
    requested_roles = [_require_text(v, "input.requested_roles") for v in requested]
    unknown_roles = set(requested_roles) - set(roles)
    if unknown_roles:
        raise SelectionError(f"input.requested_roles: unknown roles {sorted(unknown_roles)}")
    raw_candidates = input_raw.get("candidates")
    if not isinstance(raw_candidates, list) or not raw_candidates or len(raw_candidates) > MAX_CANDIDATES:
        raise SelectionError(f"input.candidates: 1..{MAX_CANDIDATES} candidates required")
    candidates = [validate_candidate(row, index) for index, row in enumerate(raw_candidates)]
    keys = [candidate_key(candidate) for candidate in candidates]
    if len(keys) != len(set(keys)):
        raise SelectionError("input.candidates: duplicate route/provider/model identity")

    selected: dict[str, dict[str, Any]] = {}
    selected_keys: set[tuple[str, str, str, str]] = set()
    selections: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    overall_diversity = "satisfied"

    for role_name in requested_roles:
        role = roles[role_name]
        eligible: list[tuple[dict[str, Any], tuple[Any, ...], list[str]]] = []
        for candidate in candidates:
            reasons, score = evaluate_candidate(candidate, role, policy, evidence_rank)
            key = candidate_key(candidate)
            if not policy.get("allow_candidate_reuse", False) and key in selected_keys:
                reasons.append("CANDIDATE_ALREADY_SELECTED")
            if reasons:
                if len(rejections) < MAX_REJECTIONS:
                    rejections.append({
                        "role": role_name,
                        "candidate": dict(zip(("host", "route_id", "provider_id", "model_id"), key)),
                        "reason_codes": sorted(set(reasons)),
                    })
                continue
            gaps = diversity_gaps(candidate, role, selected, policy["diversity_dimensions"])
            eligible.append((candidate, score, gaps))
        if not eligible:
            raise SelectionError(f"role {role_name}: no eligible receipted candidate")
        diverse = [row for row in eligible if not row[2]]
        pool = diverse or eligible
        chosen, _score, gaps = max(pool, key=lambda row: (row[1], tuple(reversed(candidate_key(row[0])))))
        diversity_status = "satisfied" if not gaps else "degraded"
        if gaps:
            overall_diversity = "degraded"
        selected[role_name] = chosen
        selected_keys.add(candidate_key(chosen))
        capability_refs = {
            capability: chosen["capabilities"][capability]["receipt_ref"]
            for capability in role.required_capabilities
        }
        selections.append({
            "role": role_name,
            "host": chosen["host"],
            "route_id": chosen["route_id"],
            "route_fingerprint": chosen["route_fingerprint"],
            "account_scope": chosen["account_scope"],
            "catalogue_observed_at": chosen["catalogue_observed_at"],
            "provider_id": chosen["provider_id"],
            "model_id": chosen["model_id"],
            "model_family": chosen["model_family"],
            "capability_evidence_refs": capability_refs,
            "score_components": {
                "route_health": chosen["route_health"],
                "context_window": chosen["context_window"],
                "cost_class": chosen["cost_class"],
                "latency_class": chosen["latency_class"],
            },
            "diversity_status": diversity_status,
            "diversity_gaps": gaps,
        })

    return {
        "schema_version": RECEIPT_VERSION,
        "selection_id": selection_id,
        "attempt_scope": attempt_scope,
        "policy_digest": digest(policy_raw),
        "input_digest": digest(input_raw),
        "selections": selections,
        "rejections": sorted(rejections, key=lambda row: (row["role"], row["candidate"]["host"], row["candidate"]["route_id"], row["candidate"]["model_id"])),
        "diversity_status": overall_diversity,
        "provider_executions": 0,
        "dispatch_authority": False,
        "authority_ceiling": "candidate_route_selection_only",
        "proof_ceiling": policy["proof_ceiling"],
    }


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SelectionError(f"{path}: cannot read JSON: {error}") from error
    if not isinstance(value, dict):
        raise SelectionError(f"{path}: JSON root must be an object")
    return value


def write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(receipt) + b"\n")
