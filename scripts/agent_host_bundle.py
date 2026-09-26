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
IDENTITY_VERSION = "eliot.agent-host-bundle-identity.v2"
# Skill-pack declaration contract. The BLAKE3 content/pack recipe is owned by
# SkillPackService in crates/eliot-engine/src/host.rs (`canonical_skill_content_hash`
# plus `name:content_hash\n` pack material in manifest order, final LF included).
# Python packaging never reimplements that primitive: it calls the reference BLAKE3
# primitive (same algorithm lineage as the `blake3` crate pinned in Cargo.lock) with
# the exact owner recipe, guarded by the normative empty-input test vector below and
# by the committed manifest pins as parity vectors on every run. Any deviation in
# either direction fails closed before publication. If the primitive is unavailable,
# verification fails explicitly instead of degrading to shape-only metadata.
SKILL_PACK_SCHEMA_VERSION = "eliot-agent-skill-pack-v1"
SKILL_PACK_HASH_ALGORITHM = "blake3(name:content_blake3 joined with LF in manifest order)"
BLAKE3_EMPTY_INPUT_HEX = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
# Structural cap for manifest parses whose own limits live inside the manifest.
MANIFEST_PARSE_BYTES_MAX = 1024 * 1024
# Declared payload copy modes. A file payload must be a verbatim byte copy; a tree
# payload must be a verbatim recursive copy. Any other mode is an unknown required
# pin format and fails explicitly.
PAYLOAD_MODE_FILE = "verbatim_copy"
PAYLOAD_MODE_TREE = "verbatim_tree_copy"
DISPOSITIONS = (
    "live-admitted",
    "unavailable-target",
    "compatibility-with-expiry",
    "removal",
)
IDENTITY_BLOCK_KEYS = ("identity", "bundle_identity", "generation")
# Manifest host-entry keys that carry caller-declared identity. They are excluded
# from the manifest-entry digest so a generation can pin its own inputs without
# circularity; declared digests are verified against recomputation instead.
DECLARED_IDENTITY_KEYS = ("identity", "bundle_identity", "generation")
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]+$")
_HEX_DIGEST_LENGTHS = frozenset({32, 40, 48, 64, 96, 128})
_DIGEST_NAME_RE = re.compile(r"(?:^|_)(sha256|sha512|sha384|sha1|md5|digest|hash|blake3)$")


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


_BLAKE3_SELF_CHECKED = False


def _blake3_hex(data: bytes) -> str:
    """Hash with the reference BLAKE3 primitive under the owner recipe.

    The algorithm stays authoritative: the primitive must reproduce the normative
    empty-input digest on first use, and every caller compares recomputation
    against manifest pins committed by the Rust owner, so neither a foreign
    primitive nor recipe drift can pass silently. SHA-256 is never substituted.
    """
    global _BLAKE3_SELF_CHECKED
    try:
        from blake3 import blake3 as _reference_blake3
    except ImportError as error:
        raise BundleError(
            "skill pack BLAKE3 verifier support is unavailable: "
            "refusing shape-only verification"
        ) from error
    if not _BLAKE3_SELF_CHECKED:
        if _reference_blake3(b"").hexdigest() != BLAKE3_EMPTY_INPUT_HEX:
            raise BundleError("skill pack BLAKE3 primitive failed its identity self-check")
        _BLAKE3_SELF_CHECKED = True
    return _reference_blake3(data).hexdigest()


def _canonical_skill_content_hash(body_text: str) -> str:
    """Reproduce `canonical_skill_content_hash` from crates/eliot-engine/src/host.rs.

    BLAKE3 over the UTF-8 encoding after CRLF→LF normalization. Normalization
    feeds the identity digest only; source and staged bytes are preserved raw.
    """
    return _blake3_hex(body_text.replace("\r\n", "\n").encode("utf-8"))


def _load_json_exact(path: Path, label: str) -> dict[str, Any]:
    """Parse a bounded manifest object, rejecting duplicate JSON keys.

    Duplicate keys would let a later pin shadow an earlier one (or vice versa)
    depending on reader order, so any duplication fails closed at every level.
    """
    try:
        size = path.stat().st_size
    except OSError as error:
        raise BundleError(f"{label}: unreadable JSON") from error
    if size > MANIFEST_PARSE_BYTES_MAX:
        raise BundleError(f"{label}: manifest exceeds structural bound")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise BundleError(f"{label}: unreadable JSON") from error

    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key, value in pairs:
            if key in mapping:
                raise BundleError(f"{label}: duplicate JSON key {key!r}")
            mapping[key] = value
        return mapping

    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as error:
        raise BundleError(f"{label}: unreadable JSON") from error
    if not isinstance(value, dict):
        raise BundleError(f"{label}: JSON root must be an object")
    return value


def _require_hex_digest(value: Any, location: str, *, label: str = "digest") -> str:
    if not isinstance(value, str) or len(value) != 64 or _HEX_DIGEST_RE.match(value) is None:
        raise BundleError(f"{location}: malformed {label} (expected 64 lowercase hex chars)")
    return value


def _safe_relative(value: str, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise BundleError(f"{field}: unsafe relative path")
    if "\x00" in value or "\\" in value:
        raise BundleError(f"{field}: unsafe relative path")
    if any(ord(char) < 0x20 for char in value):
        raise BundleError(f"{field}: unsafe relative path")
    if re.match(r"^[A-Za-z]:", value):
        raise BundleError(f"{field}: unsafe relative path")
    candidate = PurePosixPath(value)
    if not value or candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise BundleError(f"{field}: unsafe relative path")
    if any(part in FORBIDDEN_PARTS for part in candidate.parts):
        raise BundleError(f"{field}: forbidden path component")
    return candidate


def _validate_identity_node(name: str, value: Any, location: str) -> None:
    """Generically validate a Part A identity/disposition field by name.

    Digest-shaped fields must be well-formed lowercase hex, disposition fields
    must name a known disposition, and version fields must be non-empty strings.
    Every other field passes through untouched so the identity schema can grow
    without a planning change. Malformed identity fails closed.
    """
    normalized = str(name).lower().replace("-", "_")
    if normalized == "disposition":
        if isinstance(value, dict):
            # Specified Part A shape is a disposition BLOCK carrying the scalar
            # under its own "disposition" key plus digests/versions/metadata.
            # Recurse so the inner scalar, digest-likes, and versions validate
            # exactly like a scalar disposition site. A block never admits.
            for key, child in value.items():
                if not isinstance(key, str) or not key:
                    raise BundleError(f"{location}: identity mapping requires string keys")
                _validate_identity_node(key, child, f"{location}.{key}")
            return
        if value not in DISPOSITIONS:
            raise BundleError(f"{location}: unknown disposition {value!r}")
        return
    if normalized in {"schema_version", "identity_version", "version"}:
        if not isinstance(value, str) or not value.strip():
            raise BundleError(f"{location}: version must be a non-empty string")
        return
    if _DIGEST_NAME_RE.search(normalized):
        if isinstance(value, list):
            if not value:
                raise BundleError(f"{location}: malformed digest (expected lowercase hex)")
            for index, child in enumerate(value):
                _validate_identity_node(name, child, f"{location}[{index}]")
            return
        if (
            not isinstance(value, str)
            or len(value) not in _HEX_DIGEST_LENGTHS
            or _HEX_DIGEST_RE.match(value) is None
        ):
            raise BundleError(f"{location}: malformed digest (expected lowercase hex)")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise BundleError(f"{location}: identity mapping requires string keys")
            _validate_identity_node(key, child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_identity_node(name, child, f"{location}[{index}]")


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
        if b"\x00" in data:
            raise BundleError(f"{relative.as_posix()}: binary content in text payload is forbidden")
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


def load_manifest(root: Path, manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    manifest = _load_json_exact(root / manifest_path, "host bundle manifest")
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
    for host_name, host_config in hosts.items():
        if not isinstance(host_config, dict):
            raise BundleError(f"host bundle manifest entry is invalid: {host_name}")
        for key in IDENTITY_BLOCK_KEYS:
            if key in host_config and not isinstance(host_config[key], dict):
                raise BundleError(f"{host_name}: manifest identity block {key!r} must be an object")
    _validate_identity_node("manifest", manifest, "host bundle manifest")
    _validate_skill_pack_block(manifest.get("skill_pack"))
    return manifest


def _validate_skill_pack_block(block: Any) -> dict[str, Any]:
    """Require the host manifest's declared skill-pack agreement surface."""
    if not isinstance(block, dict):
        raise BundleError("host bundle manifest skill_pack block is missing")
    for key in ("manifest", "manifest_sha256", "pack_hash", "hash_algorithm", "order"):
        if block.get(key) is None:
            raise BundleError(f"host bundle manifest skill_pack.{key} is missing")
    if not isinstance(block["order"], list) or not block["order"]:
        raise BundleError("host bundle manifest skill_pack.order must be a non-empty list")
    _require_hex_digest(block["manifest_sha256"], "host bundle manifest skill_pack.manifest_sha256")
    _require_hex_digest(block["pack_hash"], "host bundle manifest skill_pack.pack_hash")
    return block


def load_skill_pack(root: Path, skill_manifest_relative: str, max_file_bytes: int) -> dict[str, Any]:
    """Load and validate the declared Skill pack; drives selection and order.

    Only manifest-declared Skills are inputs. Unrelated top-level directories are
    never enumerated here, so they cannot enter the index or payload.
    """
    manifest_relative = _safe_relative(skill_manifest_relative, "canonical_skill_manifest")
    manifest_path = root.joinpath(*manifest_relative.parts)
    manifest_bytes = _validate_source_file(manifest_path, root, max_file_bytes)
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BundleError("canonical Skill manifest: unreadable JSON") from error

    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key, value in pairs:
            if key in mapping:
                raise BundleError(f"canonical Skill manifest: duplicate JSON key {key!r}")
            mapping[key] = value
        return mapping

    try:
        document = json.loads(text, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as error:
        raise BundleError("canonical Skill manifest: unreadable JSON") from error
    if not isinstance(document, dict):
        raise BundleError("canonical Skill manifest: JSON root must be an object")
    if document.get("schema_version") != SKILL_PACK_SCHEMA_VERSION:
        raise BundleError("canonical Skill manifest schema mismatch")
    if document.get("hash_algorithm") != SKILL_PACK_HASH_ALGORITHM:
        raise BundleError("canonical Skill manifest hash algorithm is not the canonical BLAKE3 recipe")
    skills = document.get("skills")
    if not isinstance(skills, list) or not skills:
        raise BundleError("canonical Skill manifest declares no Skills")
    order: list[str] = []
    pins: dict[str, str] = {}
    for entry in skills:
        if not isinstance(entry, dict):
            raise BundleError("canonical Skill manifest Skill entry must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise BundleError("canonical Skill manifest Skill entry requires a name")
        _safe_relative(name, "Skill name")
        if "/" in name:
            raise BundleError(f"Skill name {name!r} must be a single path component")
        if name in pins:
            raise BundleError(f"canonical Skill manifest declares duplicate Skill {name!r}")
        lowered = name.lower()
        if any(known.lower() == lowered for known in order):
            raise BundleError(f"canonical Skill manifest Skill names collide on this host: {name!r}")
        pins[name] = _require_hex_digest(
            entry.get("content_blake3"),
            f"canonical Skill manifest Skill {name!r}",
            label="content_blake3",
        )
        order.append(name)
    return {
        "bytes": manifest_bytes,
        "sha256": sha256_bytes(manifest_bytes),
        "order": order,
        "pins": pins,
    }


def verify_skill_pack_agreement(
    manifest: dict[str, Any],
    skill_pack: dict[str, Any],
    *,
    canonical_skill_manifest: str,
) -> None:
    """Require exact ordered agreement between host pack block and Skill manifest."""
    block = _validate_skill_pack_block(manifest.get("skill_pack"))
    if str(block["manifest"]) != canonical_skill_manifest:
        raise BundleError("host skill_pack.manifest does not reference the canonical Skill manifest")
    if block["manifest_sha256"] != skill_pack["sha256"]:
        raise BundleError("host skill_pack.manifest_sha256 does not match recomputation")
    if str(block["hash_algorithm"]) != SKILL_PACK_HASH_ALGORITHM:
        raise BundleError("host skill_pack.hash_algorithm is not the canonical BLAKE3 recipe")
    if list(block["order"]) != skill_pack["order"]:
        raise BundleError("host skill_pack.order does not match the declared Skill order")


def _snapshot_skill_pack(
    skill_root: Path,
    skill_pack: dict[str, Any],
    limits: dict[str, int],
    root: Path,
) -> tuple[dict[str, dict[str, bytes]], str]:
    """Snapshot every declared Skill and verify its content pin plus pack hash.

    Selection and order come only from the manifest list: unrelated top-level
    directories are never opened, hashed, or copied. Returns per-Skill snapshots
    mapping paths relative to the Skill directory to validated bytes (including
    the SKILL.md body and any sibling reference files), plus the verified pack
    hash. Sibling files are covered by receipt byte accounting, not by the body
    pin: only SKILL.md carries the body's approval.
    """
    canonical_root = skill_root.resolve()
    snapshots: dict[str, dict[str, bytes]] = {}
    material: list[str] = []
    for name in skill_pack["order"]:
        skill_dir = skill_root / name
        resolved_dir = skill_dir.resolve()
        if resolved_dir != canonical_root and canonical_root not in resolved_dir.parents:
            raise BundleError(f"declared Skill escaped the canonical root: {name!r}")
        if skill_dir.is_symlink() or not skill_dir.is_dir():
            raise BundleError(f"declared Skill is missing: {name!r}")
        files: dict[str, bytes] = {}
        for file_path in _walk_tree(skill_dir):
            if file_path.is_symlink() or not file_path.is_file():
                raise BundleError(f"{name}: Skill member is not a regular file: {file_path.name!r}")
            relative = file_path.relative_to(skill_dir).as_posix()
            files[relative] = _validate_source_file(file_path, root, limits["max_file_bytes"])
        body_data = files.get("SKILL.md")
        if body_data is None:
            raise BundleError(f"declared Skill is missing its SKILL.md: {name!r}")
        try:
            body_text = body_data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BundleError(f"{name}/SKILL.md: text payload is not UTF-8") from error
        observed = _canonical_skill_content_hash(body_text)
        if observed != skill_pack["pins"][name]:
            raise BundleError(f"declared Skill content does not match its pin: {name!r}")
        material.append(f"{name}:{observed}\n")
        snapshots[name] = files
    pack_hash = _blake3_hex("".join(material).encode("utf-8"))
    return snapshots, pack_hash


def _read_snapshot(root: Path, relative: PurePosixPath, limits: dict[str, int]) -> bytes:
    """Read one source file exactly once; the returned bytes are the commitment."""
    source = root.joinpath(*relative.parts)
    resolved = source.resolve()
    if resolved != root and root not in resolved.parents:
        raise BundleError(f"source escaped repository root: {relative.as_posix()}")
    if not resolved.is_file():
        raise BundleError(f"missing bundle source: {relative.as_posix()}")
    return _validate_source_file(resolved, root, limits["max_file_bytes"])


def _tree_digest(member_entries: list[dict[str, Any]]) -> str:
    """Reproduce the manifest producer's tree-digest definition.

    Confirmed against the generation 1217-A.1 pins: SHA-256 over the canonical
    JSON (no trailing newline) of `{path, sha256, bytes}` entries sorted by
    relative path, where each member digest covers raw file bytes. The manifest
    format does not name this recipe, so any different concatenation or order is
    a schema migration, never an inferred equivalent.
    """
    ordered = sorted(member_entries, key=lambda entry: entry["path"])
    return sha256_bytes(canonical_json_bytes(ordered))


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
    _validate_identity_node("route_profile", profile, f"{host} route profile")


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


def _skill_pack_descriptions(manifest_bytes: bytes) -> dict[str, str]:
    """Read trigger descriptions from the already-validated manifest snapshot."""
    try:
        data = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError("canonical Skill manifest: unreadable JSON") from error
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


def _stage_bytes(
    data: bytes,
    staging_host: Path,
    destination: PurePosixPath,
    entries: dict[str, dict[str, Any]],
    seen_lower: set[str],
) -> None:
    """Stage validated snapshot bytes, rejecting unsafe or colliding identities."""
    safe_destination = _safe_relative(destination.as_posix(), "bundle destination")
    if safe_destination.name.lower() in FORBIDDEN_NAMES or safe_destination.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise BundleError(f"bundle destination {safe_destination.as_posix()}: credential/runtime artifact is forbidden")
    key = (PurePosixPath("host") / safe_destination).as_posix()
    if key in entries or key.lower() in seen_lower:
        raise BundleError(f"duplicate bundle destination: {key}")
    target = staging_host.joinpath(*safe_destination.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    entries[key] = {"path": key, "sha256": sha256_bytes(data), "bytes": len(data)}
    seen_lower.add(key.lower())


def _verify_file_payload(
    root: Path,
    mapping: dict[str, Any],
    host: str,
    limits: dict[str, int],
) -> tuple[PurePosixPath, bytes]:
    if mapping.get("mode", PAYLOAD_MODE_FILE) != PAYLOAD_MODE_FILE:
        raise BundleError(f"{host}: unknown file payload mode {mapping.get('mode')!r}")
    source_relative = _safe_relative(str(mapping.get("source", "")), "payload source")
    destination_relative = _safe_relative(str(mapping.get("destination", "")), "payload destination")
    expected = _require_hex_digest(mapping.get("sha256"), f"{host}: payload {source_relative.as_posix()}")
    data = _read_snapshot(root, source_relative, limits)
    if sha256_bytes(data) != expected:
        raise BundleError(f"{host}: payload bytes do not match the declared pin: {source_relative.as_posix()!r}")
    return destination_relative, data


def _verify_tree_payload(
    root: Path,
    mapping: dict[str, Any],
    host: str,
    limits: dict[str, int],
) -> list[tuple[PurePosixPath, bytes]]:
    if mapping.get("mode", PAYLOAD_MODE_TREE) != PAYLOAD_MODE_TREE:
        raise BundleError(f"{host}: unknown tree payload mode {mapping.get('mode')!r}")
    source_relative = _safe_relative(str(mapping.get("source", "")), "payload source")
    destination_relative = _safe_relative(str(mapping.get("destination", "")), "payload destination")
    source = root.joinpath(*source_relative.parts)
    if source.is_symlink() or not source.is_dir():
        raise BundleError(f"{host}: expected tree source is missing")
    declared_files = mapping.get("tree_files")
    if not isinstance(declared_files, list) or not declared_files:
        raise BundleError(f"{host}: tree payload {source_relative.as_posix()!r} declares no members")
    declared: dict[str, str] = {}
    for item in declared_files:
        if not isinstance(item, dict):
            raise BundleError(f"{host}: tree member entry must be an object")
        member = item.get("path")
        if not isinstance(member, str) or not member:
            raise BundleError(f"{host}: tree member entry requires a path string")
        _safe_relative(member, "tree member")
        if member in declared:
            raise BundleError(f"{host}: duplicate tree member {member!r}")
        declared[member] = _require_hex_digest(
            item.get("sha256"), f"{host}: tree member {member!r}"
        )
    count = mapping.get("tree_file_count")
    if not isinstance(count, int) or count != len(declared):
        raise BundleError(f"{host}: tree payload {source_relative.as_posix()!r} file count mismatch")
    expected_digest = _require_hex_digest(
        mapping.get("tree_digest_sha256"),
        f"{host}: tree payload {source_relative.as_posix()!r}",
        label="tree_digest_sha256",
    )
    observed: list[str] = []
    for file_path in _walk_tree(source):
        if file_path.is_symlink() or not file_path.is_file():
            raise BundleError(f"{host}: tree member is not a regular file: {file_path.name!r}")
        observed.append(file_path.relative_to(source).as_posix())
    observed.sort()
    if observed != sorted(declared):
        raise BundleError(f"{host}: tree payload {source_relative.as_posix()!r} member set mismatch")
    staged: list[tuple[PurePosixPath, bytes]] = []
    member_entries: list[dict[str, Any]] = []
    for member in observed:
        data = _read_snapshot(root, source_relative / PurePosixPath(member), limits)
        if sha256_bytes(data) != declared[member]:
            raise BundleError(f"{host}: tree member bytes do not match the declared pin: {member!r}")
        staged.append((destination_relative / PurePosixPath(member), data))
        member_entries.append({"path": member, "sha256": declared[member], "bytes": len(data)})
    if _tree_digest(member_entries) != expected_digest:
        raise BundleError(f"{host}: tree payload {source_relative.as_posix()!r} digest mismatch")
    return staged


def _verify_adapter_contract(
    root: Path,
    host_config: dict[str, Any],
    host: str,
    limits: dict[str, int],
) -> None:
    """Verify a declared non-null adapter contract pin; a null contract stays null."""
    contract = host_config.get("adapter_contract")
    contract_sha = host_config.get("adapter_contract_sha256")
    if contract is None:
        if contract_sha is not None:
            raise BundleError(f"{host}: adapter contract digest without a declared contract")
        return
    contract_relative = _safe_relative(str(contract), "adapter_contract")
    expected = _require_hex_digest(contract_sha, f"{host}: adapter contract")
    data = _read_snapshot(root, contract_relative, limits)
    if sha256_bytes(data) != expected:
        raise BundleError(f"{host}: adapter contract bytes do not match the declared pin")


def compute_bundle_identity(
    *,
    manifest_entry_sha256: str,
    route_profile_sha256: str,
    route_profile_source_sha256: str,
    skill_manifest_sha256: str,
    skill_index_sha256: str,
    payload_entries: list[dict[str, Any]],
) -> str:
    """Bind manifest entry, route profile (source pin and output), Skill manifest/index, and payload bytes.

    The manifest entry digest covers the host entry WITHOUT its declared
    identity blocks, so a generation can pin its own inputs without circularity.
    The route profile appears twice on purpose: the source pin (raw bytes, as the
    manifest producer hashed them) and the staged output hash (canonical JSON
    plus LF). The two domains must never be compared to each other.
    """
    document = {
        "identity_version": IDENTITY_VERSION,
        "manifest_entry_sha256": manifest_entry_sha256,
        "route_profile_sha256": route_profile_sha256,
        "route_profile_source_sha256": route_profile_source_sha256,
        "skill_manifest_sha256": skill_manifest_sha256,
        "skill_index_sha256": skill_index_sha256,
        "payload": payload_entries,
    }
    return sha256_bytes(canonical_json_bytes(document))


def _declared_identity_blocks(host_config: dict[str, Any], host: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for key in IDENTITY_BLOCK_KEYS:
        block = host_config.get(key)
        if block is not None:
            if not isinstance(block, dict):
                raise BundleError(f"{host}: manifest identity block {key!r} must be an object")
            blocks.append(block)
    return blocks


def _verify_declared_identity(
    blocks: list[dict[str, Any]],
    host: str,
    *,
    route_profile_sha256: str,
    route_profile_source_sha256: str,
    skill_manifest_sha256: str,
    skill_pack_hash: str,
    manifest_entry_sha256: str,
    bundle_identity: str,
    bundle_sha256: str,
    entries: dict[str, dict[str, Any]],
) -> None:
    """Fail closed when a manifest-declared digest contradicts recomputation.

    Only names with a fixed local meaning are compared; every other declared
    field was already shape-checked and is superseded by the computed receipt.
    A forged digest therefore never survives planning.
    """
    comparable = {
        "route_profile_sha256": route_profile_sha256,
        "route_profile_source_sha256": route_profile_source_sha256,
        "skill_manifest_sha256": skill_manifest_sha256,
        "skill_pack_sha256": skill_manifest_sha256,
        "skill_pack_hash": skill_pack_hash,
        "manifest_entry_sha256": manifest_entry_sha256,
        "bundle_identity": bundle_identity,
        "bundle_sha256": bundle_sha256,
    }
    by_bundle_path = dict(entries)
    for key, entry in entries.items():
        by_bundle_path.setdefault(key.split("/", 1)[-1] if "/" in key else key, entry)
    for block in blocks:
        for name, expected in comparable.items():
            declared = block.get(name)
            if declared is not None and declared != expected:
                raise BundleError(f"{host}: declared {name} does not match recomputation")
        for list_key in ("payload", "files"):
            declared_files = block.get(list_key)
            if declared_files is None:
                continue
            if not isinstance(declared_files, list):
                raise BundleError(f"{host}: declared {list_key} must be a list")
            for item in declared_files:
                if not isinstance(item, dict):
                    raise BundleError(f"{host}: declared {list_key} entry must be an object")
                declared_path = item.get("path")
                declared_digest = item.get("sha256", item.get("digest"))
                if not isinstance(declared_path, str) or not isinstance(declared_digest, str):
                    raise BundleError(f"{host}: declared {list_key} entry requires path and digest strings")
                actual = by_bundle_path.get(declared_path)
                if actual is None:
                    raise BundleError(f"{host}: declared {list_key} entry is unknown: {declared_path!r}")
                if actual["sha256"] != declared_digest:
                    raise BundleError(f"{host}: declared digest for {declared_path!r} does not match recomputation")


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
    output_resolved = output.resolve()
    try:
        output_resolved.relative_to(root)
        root_swallowed = True
    except ValueError:
        root_swallowed = False
    if output_resolved == root or root_swallowed:
        raise BundleError("output must not contain the repository root")
    if output.exists() and any(output.iterdir() if output.is_dir() else [output]):
        raise BundleError("output path must not contain existing data")

    limits = manifest["limits"]
    canonical_skill_manifest = str(manifest["canonical_skill_manifest"])

    # Declared Skill pack first: selection, index order, and content pins all
    # come from the manifest list. Unrelated top-level directories are never
    # opened, hashed, or copied, so they cannot enter the index or payload.
    skill_pack = load_skill_pack(root, canonical_skill_manifest, limits["max_file_bytes"])
    verify_skill_pack_agreement(
        manifest, skill_pack, canonical_skill_manifest=canonical_skill_manifest
    )
    skill_root_relative = _safe_relative(str(manifest["canonical_skill_root"]), "canonical_skill_root")
    skill_root = root.joinpath(*skill_root_relative.parts)
    if not skill_root.is_dir() or skill_root.is_symlink():
        raise BundleError("canonical Skill root is unavailable or unsafe")
    skill_snapshots, skill_pack_hash = _snapshot_skill_pack(skill_root, skill_pack, limits, root)
    if skill_pack_hash != manifest["skill_pack"]["pack_hash"]:
        raise BundleError("declared Skill pack order/hash does not match recomputation")

    # Route profile: the manifest source pin covers raw source bytes (the domain
    # the manifest producer hashed). The staged output is canonical JSON plus LF
    # and may differ; its hash is recorded separately and never compared to the
    # source pin.
    route_relative = _safe_relative(str(host_config.get("route_profile", "")), "route_profile")
    route_source = _read_snapshot(root, route_relative, limits)
    route_source_sha256 = sha256_bytes(route_source)
    expected_route_pin = _require_hex_digest(
        host_config.get("route_profile_sha256"), f"{host}: route profile"
    )
    if route_source_sha256 != expected_route_pin:
        raise BundleError(f"{host}: route profile bytes do not match the declared source pin")
    try:
        route_profile = json.loads(route_source.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"{host} route profile: unreadable JSON") from error
    if not isinstance(route_profile, dict):
        raise BundleError(f"{host} route profile: JSON root must be an object")
    _validate_route_profile(route_profile, host)

    _verify_adapter_contract(root, host_config, host, limits)

    payload = host_config.get("payload")
    if not isinstance(payload, list) or not payload:
        raise BundleError(f"{host}: payload mapping is empty")
    staged_payloads: list[tuple[PurePosixPath, bytes]] = []
    for mapping in payload:
        if not isinstance(mapping, dict) or mapping.get("kind") not in {"file", "tree"}:
            raise BundleError(f"{host}: invalid payload mapping")
        if mapping["kind"] == "file":
            staged_payloads.append(_verify_file_payload(root, mapping, host, limits))
        else:
            staged_payloads.extend(_verify_tree_payload(root, mapping, host, limits))

    skill_destination = _safe_relative(str(host_config.get("skill_destination", "")), "skill_destination")
    descriptions = _skill_pack_descriptions(skill_pack["bytes"])
    manifest_entry_sha256 = sha256_bytes(
        canonical_json_bytes({key: value for key, value in host_config.items() if key not in DECLARED_IDENTITY_KEYS})
    )
    declared_blocks = _declared_identity_blocks(host_config, host)

    output_parent = output.parent.resolve()
    output_parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix=f"eliot-{host}-bundle-", dir=output_parent))
    try:
        host_root = temp_root / "host"
        operator_root = temp_root / "operator"
        host_root.mkdir()
        operator_root.mkdir()
        entries: dict[str, dict[str, Any]] = {}
        seen_lower: set[str] = set()

        for destination, data in staged_payloads:
            _stage_bytes(data, host_root, destination, entries, seen_lower)

        skill_index: list[dict[str, Any]] = []
        for skill_name in skill_pack["order"]:
            files = skill_snapshots[skill_name]
            body_data = files["SKILL.md"]
            body_text = body_data.decode("utf-8")
            trigger = descriptions.get(skill_name) or _trigger_from_skill_body(body_text, skill_name)
            destination = skill_destination / skill_name
            for relative, data in sorted(files.items()):
                _stage_bytes(data, host_root, destination / PurePosixPath(relative), entries, seen_lower)
            skill_index.append(
                {
                    "name": skill_name,
                    "trigger_description": trigger,
                    "body_sha256": sha256_bytes(body_data),
                    "relative_body": (PurePosixPath("host") / destination / "SKILL.md").as_posix(),
                    "references_loaded": "on_reference",
                }
            )

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
        seen_lower.add("operator/skill-index.json")

        route_bytes = canonical_json_bytes(route_profile) + b"\n"
        (operator_root / "route-profile.json").write_bytes(route_bytes)
        entries["operator/route-profile.json"] = {
            "path": "operator/route-profile.json",
            "sha256": sha256_bytes(route_bytes),
            "bytes": len(route_bytes),
        }
        seen_lower.add("operator/route-profile.json")

        if len(entries) > limits["max_files"]:
            raise BundleError("bundle file count exceeds limit")
        total_bytes = sum(entry["bytes"] for entry in entries.values())
        if total_bytes > limits["max_bundle_bytes"]:
            raise BundleError("bundle bytes exceed limit")
        ordered_entries = [entries[key] for key in sorted(entries)]
        bundle_hash = sha256_bytes(canonical_json_bytes(ordered_entries))
        bundle_identity = compute_bundle_identity(
            manifest_entry_sha256=manifest_entry_sha256,
            route_profile_sha256=sha256_bytes(route_bytes),
            route_profile_source_sha256=route_source_sha256,
            skill_manifest_sha256=skill_pack["sha256"],
            skill_index_sha256=sha256_bytes(index_bytes),
            payload_entries=ordered_entries,
        )
        _verify_declared_identity(
            declared_blocks,
            host,
            route_profile_sha256=sha256_bytes(route_bytes),
            route_profile_source_sha256=route_source_sha256,
            skill_manifest_sha256=skill_pack["sha256"],
            skill_pack_hash=skill_pack_hash,
            manifest_entry_sha256=manifest_entry_sha256,
            bundle_identity=bundle_identity,
            bundle_sha256=bundle_hash,
            entries=entries,
        )
        _verify_staged_bytes(temp_root, entries, host)
        receipt = {
            "schema_version": RECEIPT_VERSION,
            "host": host,
            "identity_version": IDENTITY_VERSION,
            "route_profile_id": route_profile.get("profile_id"),
            "route_profile_sha256": sha256_bytes(route_bytes),
            "route_profile_source_sha256": route_source_sha256,
            "skill_index_sha256": sha256_bytes(index_bytes),
            "skill_manifest_sha256": skill_pack["sha256"],
            "skill_pack_hash": skill_pack_hash,
            "skill_pack_order": skill_pack["order"],
            "manifest_entry_sha256": manifest_entry_sha256,
            "bundle_identity": bundle_identity,
            "declared_identity": "verified" if declared_blocks else "absent",
            "source_pins": "verified",
            "origin_authentication": "not_authenticated_hash_pins_only",
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
            "identity_version": IDENTITY_VERSION,
            "bundle_sha256": bundle_hash,
            "bundle_identity": bundle_identity,
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
    except Exception as primary:
        shutil.rmtree(temp_root, ignore_errors=True)
        if temp_root.exists():
            primary.add_note("bundle staging cleanup failed: temporary directory remains")
        raise


def _verify_staged_bytes(staging_root: Path, entries: dict[str, dict[str, Any]], host: str) -> None:
    """Confirm the staged bytes still match the validated snapshots.

    Validation reads each source once; staging writes those exact bytes. This
    re-read detects any mutation or copy corruption between validation and
    publication, before the staging directory is promoted to the final bundle.
    """
    for key, entry in entries.items():
        staged = staging_root.joinpath(*PurePosixPath(key).parts)
        if staged.is_symlink() or not staged.is_file():
            raise BundleError(f"{host}: staged bundle file is missing: {key!r}")
        data = staged.read_bytes()
        if len(data) != entry["bytes"] or sha256_bytes(data) != entry["sha256"]:
            raise BundleError(f"{host}: staged bundle bytes changed after validation: {key!r}")


def directory_digest(path: Path) -> str:
    entries: list[dict[str, Any]] = []
    for file_path in sorted(p for p in path.rglob("*") if p.is_file()):
        if file_path.is_symlink():
            raise BundleError("materialized bundle contains a symlink")
        relative = file_path.relative_to(path).as_posix()
        entries.append({"path": relative, "sha256": sha256_file(file_path), "bytes": file_path.stat().st_size})
    return sha256_bytes(canonical_json_bytes(entries))
