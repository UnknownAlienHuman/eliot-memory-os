#!/usr/bin/env python3
"""Deterministically materialize ELIOT host integration bundles.

This module packages passive host surfaces and canonical Skills. It never installs
into a user profile, starts a provider, copies credentials/runtime state, or
claims route admission.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

MANIFEST_PATH = Path("integrations/agent-runtimes/host-bundle.manifest.json")
SCHEMA_VERSION = "eliot.agent-host-bundle-manifest.v1"
RECEIPT_VERSION = "eliot.agent-host-bundle-receipt.v1"
INDEX_VERSION = "eliot.lazy-skill-index.v1"
INSTALL_PLAN_VERSION = "eliot.agent-host-install-plan.v1"

FORBIDDEN_PARTS = {
    ".git",
    ".eliot",
    "target",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
}
FORBIDDEN_NAMES = {
    ".env",
    "credentials",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".kdbx",
}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{24,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
)
TEXT_SUFFIXES = {".json", ".md", ".txt", ".js", ".mjs", ".ts", ".toml", ".yaml", ".yml", ".py", ".sh", ".ps1"}


class BundleError(RuntimeError):
    """A stable, payload-free bundle validation failure."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(value: str, field: str) -> PurePosixPath:
    candidate = PurePosixPath(value)
    if not value or candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise BundleError(f"{field}: unsafe relative path")
    if any(part in FORBIDDEN_PARTS for part in candidate.parts):
        raise BundleError(f"{field}: forbidden path component")
    return candidate


def _allowed_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    lowered = stripped.lower()
    return (
        "${" in stripped
        or stripped.startswith("<") and stripped.endswith(">")
        or stripped.startswith("%") and stripped.endswith("%")
        or lowered.startswith("env:")
        or lowered in {"redacted", "unset", "none", "null"}
    )


def _reject_secret_values(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if isinstance(child, str) and any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS):
                if not _allowed_placeholder(child):
                    raise BundleError(f"{location}.{key}: literal secret-like configuration is forbidden")
            _reject_secret_values(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_values(child, f"{location}[{index}]")


def _validate_source_file(path: Path, root: Path, max_file_bytes: int) -> bytes:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise BundleError("source escaped repository root") from error
    if path.is_symlink():
        raise BundleError(f"{relative.as_posix()}: symlinks are forbidden")
    if not path.is_file():
        raise BundleError(f"{relative.as_posix()}: expected file")
    if any(part in FORBIDDEN_PARTS for part in relative.parts):
        raise BundleError(f"{relative.as_posix()}: forbidden path component")
    if path.name.lower() in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise BundleError(f"{relative.as_posix()}: credential/runtime artifact is forbidden")
    size = path.stat().st_size
    if size > max_file_bytes:
        raise BundleError(f"{relative.as_posix()}: file exceeds bundle limit")
    data = path.read_bytes()
    if path.suffix.lower() in TEXT_SUFFIXES:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BundleError(f"{relative.as_posix()}: text payload is not UTF-8") from error
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                raise BundleError(f"{relative.as_posix()}: secret-like literal is forbidden")
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as error:
                raise BundleError(f"{relative.as_posix()}: malformed JSON") from error
            _reject_secret_values(parsed)
    return data


def _walk_tree(path: Path) -> Iterable[Path]:
    if path.is_symlink():
        raise BundleError(f"{path}: symlink tree is forbidden")
    for current, directories, files in os.walk(path, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(directories)
        files.sort()
        for directory in directories:
            child = current_path / directory
            if child.is_symlink():
                raise BundleError(f"{child}: symlink directory is forbidden")
        for filename in files:
            yield current_path / filename


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"{label}: unreadable JSON") from error
    if not isinstance(value, dict):
        raise BundleError(f"{label}: JSON root must be an object")
    return value


def load_manifest(root: Path, manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    manifest = _load_json(root / manifest_path, "host bundle manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BundleError("host bundle manifest schema mismatch")
    hosts = manifest.get("hosts")
    limits = manifest.get("limits")
    if not isinstance(hosts, dict) or set(hosts) != {"codex", "opencode", "claude", "antigravity"}:
        raise BundleError("host bundle manifest must define exactly four hosts")
    if not isinstance(limits, dict):
        raise BundleError("host bundle limits are missing")
    for key in ("max_file_bytes", "max_bundle_bytes", "max_files"):
        if not isinstance(limits.get(key), int) or limits[key] <= 0:
            raise BundleError(f"host bundle limit {key} is invalid")
    _safe_relative(str(manifest.get("canonical_skill_root", "")), "canonical_skill_root")
    _safe_relative(str(manifest.get("canonical_skill_manifest", "")), "canonical_skill_manifest")
    return manifest


def _validate_route_profile(profile: dict[str, Any], host: str) -> None:
    if profile.get("schema_version") != "eliot.agent-route-profile.v1":
        raise BundleError(f"{host}: route profile schema mismatch")
    if profile.get("host_family") != host:
        raise BundleError(f"{host}: route profile host mismatch")
    routes = profile.get("execution_routes")
    if not isinstance(routes, list):
        raise BundleError(f"{host}: execution routes missing")
    primary = [route for route in routes if isinstance(route, dict) and route.get("role") == "primary_candidate"]
    if len(primary) != 1:
        raise BundleError(f"{host}: exactly one primary candidate is required")
    launch = primary[0].get("launch", {})
    if launch.get("argv_construction") != "typed_no_shell" or launch.get("shell") is not False:
        raise BundleError(f"{host}: primary launch must be typed and shell-free")
    if launch.get("environment_policy") != "allowlist":
        raise BundleError(f"{host}: primary environment must be allowlisted")
    model = primary[0].get("model_selection", {})
    if model.get("fixed_model_id") is not None or model.get("per_attempt_receipt") is not True:
        raise BundleError(f"{host}: model selection must be dynamic and receipted")
    skills = profile.get("skills", {})
    if skills.get("canonical_source") != "integrations/agent-skills" or skills.get("delivery") != "lazy":
        raise BundleError(f"{host}: canonical lazy Skills contract drifted")
    mcp = profile.get("mcp", {})
    if mcp.get("raw_store_access") is not False or mcp.get("tool_visibility") != "task_relative_lazy":
        raise BundleError(f"{host}: MCP boundary drifted")
    coordination = profile.get("coordination", {})
    if coordination.get("message_transport") != "durable_mailbox":
        raise BundleError(f"{host}: durable mailbox is required")
    if coordination.get("meeting_form") != "concilium_over_sealed_evidence":
        raise BundleError(f"{host}: Concilium contract is required")


def _trigger_from_skill_body(text: str, fallback: str) -> str:
    lines = [line.strip() for line in text.splitlines()]
    paragraph: list[str] = []
    for line in lines:
        if not line or line == "---":
            if paragraph:
                break
            continue
        if line.startswith("#") or line.startswith("name:") or line.startswith("description:"):
            continue
        paragraph.append(line)
        if len(" ".join(paragraph)) >= 40:
            break
    description = " ".join(paragraph).strip()
    return description[:280] if description else f"Activate the {fallback} ELIOT procedure."


def _skill_manifest_descriptions(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    data = _load_json(path, "canonical Skill manifest")
    candidates = data.get("skills", [])
    if not isinstance(candidates, list):
        return {}
    descriptions: dict[str, str] = {}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("id")
        description = item.get("trigger_description") or item.get("description") or item.get("trigger")
        if isinstance(name, str) and isinstance(description, str) and description.strip():
            descriptions[name] = description.strip()[:280]
    return descriptions


def _copy_payload(
    root: Path,
    source: Path,
    destination: PurePosixPath,
    staging_host: Path,
    limits: dict[str, int],
    entries: dict[str, dict[str, Any]],
) -> None:
    def copy_one(file_path: Path, destination_path: PurePosixPath) -> None:
        safe_destination = _safe_relative(destination_path.as_posix(), "bundle destination")
        key = (PurePosixPath("host") / safe_destination).as_posix()
        if key in entries:
            raise BundleError(f"duplicate bundle destination: {key}")
        data = _validate_source_file(file_path, root, limits["max_file_bytes"])
        target = staging_host.joinpath(*safe_destination.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        entries[key] = {"path": key, "sha256": sha256_bytes(data), "bytes": len(data)}

    if source.is_file():
        copy_one(source, destination)
        return
    if not source.is_dir():
        raise BundleError(f"missing bundle source: {source.relative_to(root).as_posix()}")
    for file_path in _walk_tree(source):
        relative = PurePosixPath(file_path.relative_to(source).as_posix())
        copy_one(file_path, destination / relative)


def materialize_host_bundle(
    root: Path,
    host: str,
    output: Path,
    manifest_path: Path = MANIFEST_PATH,
) -> dict[str, Any]:
    root = root.resolve()
    manifest = load_manifest(root, manifest_path)
    host_config = manifest["hosts"].get(host)
    if not isinstance(host_config, dict):
        raise BundleError(f"unsupported host: {host}")
    if output.exists() and any(output.iterdir() if output.is_dir() else [output]):
        raise BundleError("output path must not contain existing data")

    limits = manifest["limits"]
    route_relative = _safe_relative(str(host_config.get("route_profile", "")), "route_profile")
    route_path = root.joinpath(*route_relative.parts)
    route_profile = _load_json(route_path, f"{host} route profile")
    _validate_route_profile(route_profile, host)

    payload = host_config.get("payload")
    if not isinstance(payload, list) or not payload:
        raise BundleError(f"{host}: payload mapping is empty")
    skill_destination = _safe_relative(str(host_config.get("skill_destination", "")), "skill_destination")
    skill_root_relative = _safe_relative(str(manifest["canonical_skill_root"]), "canonical_skill_root")
    skill_root = root.joinpath(*skill_root_relative.parts)
    if not skill_root.is_dir() or skill_root.is_symlink():
        raise BundleError("canonical Skill root is unavailable or unsafe")
    description_manifest = root / manifest["canonical_skill_manifest"]
    descriptions = _skill_manifest_descriptions(description_manifest)

    output_parent = output.parent.resolve()
    output_parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix=f"eliot-{host}-bundle-", dir=output_parent))
    try:
        host_root = temp_root / "host"
        operator_root = temp_root / "operator"
        host_root.mkdir()
        operator_root.mkdir()
        entries: dict[str, dict[str, Any]] = {}

        for mapping in payload:
            if not isinstance(mapping, dict) or mapping.get("kind") not in {"file", "tree"}:
                raise BundleError(f"{host}: invalid payload mapping")
            source_relative = _safe_relative(str(mapping.get("source", "")), "payload source")
            destination_relative = _safe_relative(str(mapping.get("destination", "")), "payload destination")
            source = root.joinpath(*source_relative.parts)
            if mapping["kind"] == "file" and not source.is_file():
                raise BundleError(f"{host}: expected file source is missing")
            if mapping["kind"] == "tree" and not source.is_dir():
                raise BundleError(f"{host}: expected tree source is missing")
            _copy_payload(root, source, destination_relative, host_root, limits, entries)

        skill_index: list[dict[str, Any]] = []
        for skill_dir in sorted(path for path in skill_root.iterdir() if path.is_dir()):
            if skill_dir.is_symlink():
                raise BundleError(f"{skill_dir.name}: Skill symlink is forbidden")
            skill_name = skill_dir.name
            _safe_relative(skill_name, "Skill name")
            body = skill_dir / "SKILL.md"
            body_data = _validate_source_file(body, root, limits["max_file_bytes"])
            body_text = body_data.decode("utf-8")
            trigger = descriptions.get(skill_name) or _trigger_from_skill_body(body_text, skill_name)
            destination = skill_destination / skill_name
            _copy_payload(root, skill_dir, destination, host_root, limits, entries)
            skill_index.append(
                {
                    "name": skill_name,
                    "trigger_description": trigger,
                    "body_sha256": sha256_bytes(body_data),
                    "relative_body": (PurePosixPath("host") / destination / "SKILL.md").as_posix(),
                    "references_loaded": "on_reference",
                }
            )
        if not skill_index:
            raise BundleError("canonical Skill pack is empty")

        skill_index_document = {
            "schema_version": INDEX_VERSION,
            "host": host,
            "delivery": "lazy",
            "entries": skill_index,
        }
        index_bytes = canonical_json_bytes(skill_index_document) + b"\n"
        (operator_root / "skill-index.json").write_bytes(index_bytes)
        entries["operator/skill-index.json"] = {
            "path": "operator/skill-index.json",
            "sha256": sha256_bytes(index_bytes),
            "bytes": len(index_bytes),
        }

        route_bytes = canonical_json_bytes(route_profile) + b"\n"
        (operator_root / "route-profile.json").write_bytes(route_bytes)
        entries["operator/route-profile.json"] = {
            "path": "operator/route-profile.json",
            "sha256": sha256_bytes(route_bytes),
            "bytes": len(route_bytes),
        }

        if len(entries) > limits["max_files"]:
            raise BundleError("bundle file count exceeds limit")
        total_bytes = sum(entry["bytes"] for entry in entries.values())
        if total_bytes > limits["max_bundle_bytes"]:
            raise BundleError("bundle bytes exceed limit")
        ordered_entries = [entries[key] for key in sorted(entries)]
        bundle_hash = sha256_bytes(canonical_json_bytes(ordered_entries))
        receipt = {
            "schema_version": RECEIPT_VERSION,
            "host": host,
            "route_profile_id": route_profile.get("profile_id"),
            "route_profile_sha256": sha256_bytes(route_bytes),
            "skill_index_sha256": sha256_bytes(index_bytes),
            "bundle_sha256": bundle_hash,
            "file_count": len(ordered_entries),
            "total_bytes": total_bytes,
            "files": ordered_entries,
            "contains_credentials": False,
            "contains_runtime_state": False,
            "provider_executions": 0,
            "route_admitted": False,
            "proof_ceiling": "DETERMINISTIC_PACKAGE_SHAPE_ONLY",
        }
        receipt_bytes = canonical_json_bytes(receipt) + b"\n"
        (operator_root / "bundle-receipt.json").write_bytes(receipt_bytes)

        install_plan = {
            "schema_version": INSTALL_PLAN_VERSION,
            "host": host,
            "bundle_sha256": bundle_hash,
            "source_subdirectory": "host",
            "destination_hint": host_config.get("destination_hint"),
            "mode": "copy_after_explicit_operator_action",
            "overwrite_existing": False,
            "copy_credentials": False,
            "copy_runtime_state": False,
            "post_copy_route_admission_required": True,
            "executes_provider": False,
        }
        (operator_root / "install-plan.json").write_bytes(canonical_json_bytes(install_plan) + b"\n")

        if output.exists():
            if output.is_dir():
                output.rmdir()
            else:
                output.unlink()
        temp_root.replace(output)
        return receipt
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise


def directory_digest(path: Path) -> str:
    entries: list[dict[str, Any]] = []
    for file_path in sorted(p for p in path.rglob("*") if p.is_file()):
        if file_path.is_symlink():
            raise BundleError("materialized bundle contains a symlink")
        relative = file_path.relative_to(path).as_posix()
        entries.append({"path": relative, "sha256": sha256_file(file_path), "bytes": file_path.stat().st_size})
    return sha256_bytes(canonical_json_bytes(entries))
