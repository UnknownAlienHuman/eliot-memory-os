#!/usr/bin/env python3
"""Development-only deterministic oracle for ELIOT route/model selection.

This module never executes a provider, dispatches an AgentAttempt, owns a host
catalogue, or emits the canonical Rust ``RoutingReceipt``. Its output is a
synthetic differential-test candidate that must not enter production admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Mapping, Sequence

POLICY_VERSION = "eliot.agent-model-selection-policy.v1"
INPUT_VERSION = "eliot.agent-model-selection-input.v1"
OUTPUT_VERSION = "eliot.agent-model-selection-oracle-candidate.v1"
PROOF_CEILING = (
    "Development differential oracle over supplied synthetic inputs only; "
    "no current-account, capability, provider, dispatch, or AgentAttempt proof."
)
ROUTE_HEALTH = {"unknown": 0, "degraded": 1, "healthy": 2}
CAPABILITY_STATUSES = {"supported", "unsupported", "unknown"}
DIVERSITY_FIELDS = {
    "host", "route_id", "route_fingerprint", "account_scope", "provider_id", "model_family"
}
FORBIDDEN_KEY_FRAGMENTS = (
    "api_key", "apikey", "authorization", "bearer", "cookie", "credential",
    "password", "private_key", "secret", "token",
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES = 256
MAX_REJECTIONS = 512
MAX_ROLES = 64
MAX_LIST_ITEMS = 256


class SelectionError(ValueError):
    """Stable selector input, policy, or immutable-output failure."""


@dataclass(frozen=True)
class RolePolicy:
    role: str
    required_capabilities: tuple[str, ...]
    minimum_context_window: int
    maximum_cost_class: int
    maximum_latency_class: int
    diversity_from: tuple[str, ...]


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise SelectionError(f"canonical JSON required: {error}") from error


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SelectionError(f"{field}: object required")
    return value


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SelectionError(f"{field}: nonblank string required")
    normalized = value.strip()
    if len(normalized) > 1024:
        raise SelectionError(f"{field}: value is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise SelectionError(f"{field}: control characters are forbidden")
    return normalized


def _require_int(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = 10_000_000,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SelectionError(f"{field}: integer in [{minimum}, {maximum}] required")
    return value


def _require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise SelectionError(f"{field}: boolean required")
    return value


def _require_unique_text_list(
    value: Any,
    field: str,
    *,
    allow_empty: bool = False,
    maximum: int = MAX_LIST_ITEMS,
) -> list[str]:
    if not isinstance(value, list):
        raise SelectionError(f"{field}: list required")
    if (not allow_empty and not value) or len(value) > maximum:
        minimum = 0 if allow_empty else 1
        raise SelectionError(f"{field}: {minimum}..{maximum} items required")
    normalized = [_require_text(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(normalized) != len(set(normalized)):
        raise SelectionError(f"{field}: unique values required")
    return normalized


def _require_sha256(value: Any, field: str) -> str:
    normalized = _require_text(value, field)
    if not SHA256_RE.fullmatch(normalized):
        raise SelectionError(f"{field}: canonical sha256:<64 lowercase hex> required")
    return normalized


def _require_rfc3339(value: Any, field: str) -> str:
    normalized = _require_text(value, field)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise SelectionError(f"{field}: RFC3339 timestamp required") from error
    if parsed.tzinfo is None:
        raise SelectionError(f"{field}: timezone is required")
    return normalized


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


def parse_policy(
    raw_value: Any,
) -> tuple[dict[str, Any], dict[str, RolePolicy], dict[str, int]]:
    raw = _require_mapping(raw_value, "policy")
    if raw.get("schema_version") != POLICY_VERSION:
        raise SelectionError("policy.schema_version: unsupported policy version")
    if "fixed_model_id" in raw or "default_model_id" in raw:
        raise SelectionError("policy: fixed/default model identity is forbidden")

    proof_ceiling = _require_text(raw.get("proof_ceiling"), "policy.proof_ceiling")
    if proof_ceiling != PROOF_CEILING:
        raise SelectionError("policy.proof_ceiling: development oracle ceiling mismatch")
    allow_candidate_reuse = _require_bool(
        raw.get("allow_candidate_reuse"),
        "policy.allow_candidate_reuse",
    )
    allowed_hosts = _require_unique_text_list(
        raw.get("allowed_host_families"),
        "policy.allowed_host_families",
    )

    order = _require_unique_text_list(raw.get("evidence_order"), "policy.evidence_order")
    if len(order) < 2:
        raise SelectionError("policy.evidence_order: at least two values required")
    evidence_rank = {value: index for index, value in enumerate(order)}
    minimum = _require_text(
        raw.get("minimum_capability_evidence"),
        "policy.minimum_capability_evidence",
    )
    if minimum not in evidence_rank:
        raise SelectionError("policy.minimum_capability_evidence: value is not in evidence_order")

    role_rows = raw.get("roles")
    if not isinstance(role_rows, list) or not role_rows or len(role_rows) > MAX_ROLES:
        raise SelectionError(f"policy.roles: 1..{MAX_ROLES} items required")
    roles: dict[str, RolePolicy] = {}
    for index, raw_row in enumerate(role_rows):
        row = _require_mapping(raw_row, f"policy.roles[{index}]")
        role = _require_text(row.get("role"), f"policy.roles[{index}].role")
        if role in roles:
            raise SelectionError(f"policy.roles[{index}].role: duplicate role")
        caps = _require_unique_text_list(
            row.get("required_capabilities"),
            f"policy.roles[{index}].required_capabilities",
        )
        diversity = _require_unique_text_list(
            row.get("diversity_from"),
            f"policy.roles[{index}].diversity_from",
            allow_empty=True,
            maximum=MAX_ROLES,
        )
        roles[role] = RolePolicy(
            role=role,
            required_capabilities=tuple(caps),
            minimum_context_window=_require_int(
                row.get("minimum_context_window"),
                f"policy.roles[{index}].minimum_context_window",
            ),
            maximum_cost_class=_require_int(
                row.get("maximum_cost_class"),
                f"policy.roles[{index}].maximum_cost_class",
                maximum=100,
            ),
            maximum_latency_class=_require_int(
                row.get("maximum_latency_class"),
                f"policy.roles[{index}].maximum_latency_class",
                maximum=100,
            ),
            diversity_from=tuple(diversity),
        )
    for role in roles.values():
        unknown = set(role.diversity_from) - set(roles)
        if unknown:
            raise SelectionError(f"policy role {role.role}: unknown diversity roles {sorted(unknown)}")

    normalized_lists: dict[str, list[str]] = {}
    for field in (
        "admitted_route_statuses",
        "current_catalogue_statuses",
        "dispatchable_availability",
        "dispatchable_quota_statuses",
        "diversity_dimensions",
    ):
        normalized_lists[field] = _require_unique_text_list(raw.get(field), f"policy.{field}")
    unknown_dimensions = set(normalized_lists["diversity_dimensions"]) - DIVERSITY_FIELDS
    if unknown_dimensions:
        raise SelectionError(
            f"policy.diversity_dimensions: unsupported fields {sorted(unknown_dimensions)}"
        )

    normalized_policy = dict(raw)
    normalized_policy["proof_ceiling"] = proof_ceiling
    normalized_policy["allow_candidate_reuse"] = allow_candidate_reuse
    normalized_policy["allowed_host_families"] = allowed_hosts
    normalized_policy["evidence_order"] = order
    normalized_policy.update(normalized_lists)
    return normalized_policy, roles, evidence_rank


def validate_candidate(
    candidate_value: Any,
    index: int,
    *,
    allowed_hosts: set[str],
    evidence_rank: Mapping[str, int],
) -> dict[str, Any]:
    candidate = _require_mapping(candidate_value, f"candidates[{index}]")
    required_text = (
        "host",
        "route_id",
        "account_scope",
        "catalogue_status",
        "route_admission",
        "route_health",
        "provider_id",
        "model_id",
        "model_family",
        "availability",
        "quota_status",
    )
    normalized = dict(candidate)
    for field in required_text:
        normalized[field] = _require_text(candidate.get(field), f"candidates[{index}].{field}")
    normalized["route_fingerprint"] = _require_sha256(
        candidate.get("route_fingerprint"),
        f"candidates[{index}].route_fingerprint",
    )
    normalized["catalogue_observed_at"] = _require_rfc3339(
        candidate.get("catalogue_observed_at"),
        f"candidates[{index}].catalogue_observed_at",
    )
    if normalized["host"] not in allowed_hosts:
        raise SelectionError(f"candidates[{index}].host: not allowed by fixture policy")
    if normalized["route_health"] not in ROUTE_HEALTH:
        raise SelectionError(f"candidates[{index}].route_health: unsupported value")
    for field, maximum in (
        ("context_window", 100_000_000),
        ("cost_class", 100),
        ("latency_class", 100),
    ):
        normalized[field] = _require_int(
            candidate.get(field),
            f"candidates[{index}].{field}",
            maximum=maximum,
        )
    normalized["role_eligibility"] = tuple(
        _require_unique_text_list(
            candidate.get("role_eligibility"),
            f"candidates[{index}].role_eligibility",
            maximum=MAX_ROLES,
        )
    )
    capabilities = _require_mapping(
        candidate.get("capabilities"),
        f"candidates[{index}].capabilities",
    )
    if len(capabilities) > MAX_LIST_ITEMS:
        raise SelectionError(f"candidates[{index}].capabilities: too many entries")
    normalized_caps: dict[str, dict[str, str]] = {}
    for name, evidence_value in capabilities.items():
        cap = _require_text(name, f"candidates[{index}].capabilities")
        if cap in normalized_caps:
            raise SelectionError(f"candidates[{index}].capabilities: duplicate normalized name")
        evidence = _require_mapping(
            evidence_value,
            f"candidates[{index}].capabilities.{cap}",
        )
        status = _require_text(
            evidence.get("status"),
            f"candidates[{index}].capabilities.{cap}.status",
        )
        if status not in CAPABILITY_STATUSES:
            raise SelectionError(
                f"candidates[{index}].capabilities.{cap}.status: unsupported value"
            )
        evidence_class = _require_text(
            evidence.get("evidence"),
            f"candidates[{index}].capabilities.{cap}.evidence",
        )
        if evidence_class not in evidence_rank:
            raise SelectionError(
                f"candidates[{index}].capabilities.{cap}.evidence: unknown evidence class"
            )
        normalized_caps[cap] = {
            "status": status,
            "evidence": evidence_class,
            "receipt_ref": _require_text(
                evidence.get("receipt_ref"),
                f"candidates[{index}].capabilities.{cap}.receipt_ref",
            ),
        }
    normalized["capabilities"] = normalized_caps
    return normalized


def candidate_key(candidate: Mapping[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        candidate["host"],
        candidate["route_id"],
        candidate["route_fingerprint"],
        candidate["account_scope"],
        candidate["provider_id"],
        candidate["model_id"],
    )


def evaluate_candidate(
    candidate: Mapping[str, Any],
    role: RolePolicy,
    policy: Mapping[str, Any],
    evidence_rank: Mapping[str, int],
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
        rank = evidence_rank[receipt["evidence"]]
        if rank < minimum_rank:
            reasons.append(f"CAPABILITY_EVIDENCE_TOO_WEAK:{capability}")
        capability_ranks.append(rank)
    score = (
        ROUTE_HEALTH[candidate["route_health"]],
        min(capability_ranks, default=-1),
        candidate["context_window"],
        -candidate["cost_class"],
        -candidate["latency_class"],
        tuple(-ord(character) for character in "|".join(candidate_key(candidate))),
    )
    return sorted(set(reasons)), score


def diversity_gaps(
    candidate: Mapping[str, Any],
    role: RolePolicy,
    selected: Mapping[str, Mapping[str, Any]],
    dimensions: Sequence[str],
) -> list[str]:
    gaps: list[str] = []
    for prior_role in role.diversity_from:
        prior = selected.get(prior_role)
        if prior is None:
            continue
        for dimension in dimensions:
            if candidate[dimension] == prior[dimension]:
                gaps.append(f"{prior_role}:{dimension}")
    return sorted(set(gaps))


def select_models(policy_value: Any, input_value: Any) -> dict[str, Any]:
    policy_raw = _require_mapping(policy_value, "policy")
    input_raw = _require_mapping(input_value, "input")
    reject_secret_bearing_shape(policy_raw, "$.policy")
    reject_secret_bearing_shape(input_raw, "$.input")
    policy, roles, evidence_rank = parse_policy(policy_raw)
    if input_raw.get("schema_version") != INPUT_VERSION:
        raise SelectionError("input.schema_version: unsupported input version")
    selection_id = _require_text(input_raw.get("selection_id"), "input.selection_id")
    attempt_scope = _require_text(input_raw.get("attempt_scope"), "input.attempt_scope")
    requested_roles = _require_unique_text_list(
        input_raw.get("requested_roles"),
        "input.requested_roles",
        maximum=MAX_ROLES,
    )
    unknown_roles = set(requested_roles) - set(roles)
    if unknown_roles:
        raise SelectionError(f"input.requested_roles: unknown roles {sorted(unknown_roles)}")
    raw_candidates = input_raw.get("candidates")
    if not isinstance(raw_candidates, list) or not raw_candidates or len(raw_candidates) > MAX_CANDIDATES:
        raise SelectionError(f"input.candidates: 1..{MAX_CANDIDATES} candidates required")
    allowed_hosts = set(policy["allowed_host_families"])
    candidates = [
        validate_candidate(
            row,
            index,
            allowed_hosts=allowed_hosts,
            evidence_rank=evidence_rank,
        )
        for index, row in enumerate(raw_candidates)
    ]
    keys = [candidate_key(candidate) for candidate in candidates]
    if len(keys) != len(set(keys)):
        raise SelectionError("input.candidates: duplicate route/account/provider/model identity")

    selected: dict[str, dict[str, Any]] = {}
    selected_keys: set[tuple[str, str, str, str, str, str]] = set()
    selections: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    overall_diversity = "satisfied"

    for role_name in requested_roles:
        role = roles[role_name]
        eligible: list[tuple[dict[str, Any], tuple[Any, ...], list[str]]] = []
        for candidate in candidates:
            reasons, score = evaluate_candidate(candidate, role, policy, evidence_rank)
            key = candidate_key(candidate)
            if not policy["allow_candidate_reuse"] and key in selected_keys:
                reasons.append("CANDIDATE_ALREADY_SELECTED")
            if reasons:
                if len(rejections) < MAX_REJECTIONS:
                    rejections.append(
                        {
                            "role": role_name,
                            "candidate": {
                                "host": candidate["host"],
                                "route_id": candidate["route_id"],
                                "route_fingerprint": candidate["route_fingerprint"],
                                "account_scope": candidate["account_scope"],
                                "provider_id": candidate["provider_id"],
                                "model_id": candidate["model_id"],
                            },
                            "reason_codes": sorted(set(reasons)),
                        }
                    )
                continue
            gaps = diversity_gaps(
                candidate,
                role,
                selected,
                policy["diversity_dimensions"],
            )
            eligible.append((candidate, score, gaps))
        if not eligible:
            raise SelectionError(f"role {role_name}: no eligible synthetic candidate")
        diverse = [row for row in eligible if not row[2]]
        pool = diverse or eligible
        chosen, _score, gaps = max(
            pool,
            key=lambda row: (row[1], tuple(reversed(candidate_key(row[0])))),
        )
        diversity_status = "satisfied" if not gaps else "degraded"
        if gaps:
            overall_diversity = "degraded"
        selected[role_name] = chosen
        selected_keys.add(candidate_key(chosen))
        capability_refs = {
            capability: chosen["capabilities"][capability]["receipt_ref"]
            for capability in role.required_capabilities
        }
        selections.append(
            {
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
            }
        )

    return {
        "schema_version": OUTPUT_VERSION,
        "artifact_class": "development_only_differential_oracle",
        "production_import_allowed": False,
        "rust_owner": "eliot-agent-coordinator::RoutingReceipt",
        "selection_id": selection_id,
        "attempt_scope": attempt_scope,
        "policy_digest": digest(policy_raw),
        "input_digest": digest(input_raw),
        "selections": selections,
        "rejections": sorted(
            rejections,
            key=lambda row: (
                row["role"],
                row["candidate"]["host"],
                row["candidate"]["route_id"],
                row["candidate"]["route_fingerprint"],
                row["candidate"]["account_scope"],
                row["candidate"]["model_id"],
            ),
        ),
        "diversity_status": overall_diversity,
        "provider_executions": 0,
        "dispatch_authority": False,
        "authority_ceiling": "candidate_route_selection_only",
        "proof_ceiling": PROOF_CEILING,
    }


def read_json(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > MAX_JSON_BYTES:
            raise SelectionError(f"{path}: JSON exceeds {MAX_JSON_BYTES} bytes")
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except SelectionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SelectionError(f"{path}: cannot read JSON: {error}") from error
    if not isinstance(value, dict):
        raise SelectionError(f"{path}: JSON root must be an object")
    return value


def _read_existing_candidate(path: Path, payload: bytes) -> bool:
    try:
        existing = path.read_bytes()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise SelectionError(f"{path}: cannot read existing candidate: {error}") from error
    if existing == payload:
        return True
    raise SelectionError(f"{path}: immutable candidate conflict")


def write_candidate(path: Path, candidate: Mapping[str, Any]) -> None:
    """Publish one immutable candidate with create-new/idempotent semantics."""
    payload = canonical_bytes(candidate) + b"\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SelectionError(f"{path.parent}: cannot create output directory: {error}") from error
    if _read_existing_candidate(path, payload):
        return

    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

        try:
            os.link(temporary, path)
        except FileExistsError:
            if not _read_existing_candidate(path, payload):
                raise AssertionError("unreachable")
        except OSError as error:
            raise SelectionError(f"{path}: atomic create-new publication failed: {error}") from error
    except SelectionError:
        raise
    except OSError as error:
        raise SelectionError(f"{path}: cannot publish candidate: {error}") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise SelectionError(f"{temporary}: cannot remove staging file: {error}") from error
