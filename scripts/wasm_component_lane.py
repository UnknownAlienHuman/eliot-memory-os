#!/usr/bin/env python3
"""Affected-component WASM build/test lane selector and evidence helper.

Owning issue: #764 ([E-LANE]). Implements (never Closes) the scripts-owned
slice: registry-only module resolution, manifest/world/capsule freeze,
isolated target-root derivation, exact-manifest build/test argv, affected
selection, and SHA-256-bound receipts with cold/warm observations.

Accepted contracts consumed READ-ONLY (never mutated or redefined here):

- ``crates/modules/eliot-wasm-runtime/src/component_contract.rs``
  (``TYPED_PACKAGE_ID = "eliot:current@0.1.0"``, ``TYPED_ABI_REVISION = 1``,
  the six frozen typed worlds, ``TYPED_ENGINE_IMPLEMENTATION`` /
  ``TYPED_ENGINE_VERSION``);
- ``crates/modules/eliot-wasm-runtime/src/capsule.rs``
  (``ModuleContractKit`` / ``ModuleTestCapsule`` / ``invoke_typed`` binding
  rules mirrored below: exact package/world/ABI match, declared
  import/export identity, kit-digest-bound capsule, domain-operation-only
  execution);
- ``bins/eliot-wasm-host/wit/typed/`` (frozen ``eliot:current@0.1.0`` world
  set owned by #756);
- ``rust-toolchain.toml`` (pinned channel ``1.97.1`` and guest target
  ``wasm32-wasip2`` owned by #870; this lane never installs targets or
  mutates the toolchain file).

Registry rule: this helper contains NO module list. The caller supplies a
registry mapping whose provenance must be an accepted source (per-module
``module.toml``/``Cargo.toml``/descriptor bindings admitted by the owning
guest issues; only the integrator appends the canonical shared registry).
An entry that disagrees with the frozen constants above is a
ContractChallenge, never a local override.

Safety rules: module names resolve through the registry only. Unknown,
traversal, absolute, separator, and shell-injection spellings are rejected
BEFORE any command is constructed or executed. Fixed argv only, no shell,
no ``cargo --workspace`` (exact ``-p <module>`` manifest builds), no
workspace ``target/`` reuse, no target installation, no provider,
credential, secret, or network capability.

Proof ceiling: ISOLATED_COMPONENT_EVIDENCE_ONLY. A lane receipt is not
native Product or release acceptance (#750 owns workspace verification).
Refs #764 (ordering: after #750/#870/#762; consumes #756/#758/#760).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
import tomllib

SCHEMA = "eliot-wasm-component-lane-v1"
RECEIPT_SCHEMA = "eliot-wasm-component-lane-receipt-v1"

# Frozen mirrors of the accepted contracts (provenance in the module
# docstring). Mismatch with the owning sources is a ContractChallenge.
TYPED_PACKAGE_ID = "eliot:current@0.1.0"
TYPED_ABI_REVISION = 1
GUEST_TARGET = "wasm32-wasip2"
TOOLCHAIN_CHANNEL = "1.97.1"
TYPED_ENGINE_IMPLEMENTATION = "wasmtime-component"
TYPED_ENGINE_VERSION = "47.0.4"
FROZEN_WORLDS = frozenset({
    "context-admission",
    "context-assembly",
    "cue-activation",
    "dreamer-handler",
    "memory-curation-screen",
    "dreamer-cycle",
})
LEGACY_WORLDS = frozenset({"guest", "eliot:wasm/guest"})
LEGACY_PACKAGE_ID = "eliot:wasm@1.0.0"
LEGACY_EXPORT = "run"
FROZEN_STAGES = frozenset({
    "BUILD", "ABI", "INSTANTIATION", "INVOCATION",
    "RESULT", "PARITY", "RECEIPT",
})

MAX_REGISTRY_BYTES = 65_536
MAX_MANIFEST_BYTES = 65_536
MAX_TEXT_FIELD = 512
MAX_MODULE_NAME = 64
MAX_TOOL_OUTPUT = 65_536
COMMAND_TIMEOUT = 600.0

_DISPOSITIONS = frozenset({
    "BUILD_PASS", "TEST_PASS", "NO_WORK", "SKIPPED",
    "UNAVAILABLE", "CANCELLED", "FAILED",
})

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHELL_CHARS = frozenset(";&|$`()<>{}*?!~#%^\n\r\t\"'\\")


class LaneError(ValueError):
    """Bounded reason code; never echoes untrusted input."""


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def check_module_name(name: object) -> str:
    """Validate one registry key BEFORE any lookup, read, or execution.

    Layered fail-closed codes: empty, overlong, absolute, traversal,
    separator, shell-injection, charset, then membership (by the caller).
    """
    if type(name) is not str or not name:
        raise LaneError("EMPTY_MODULE_NAME")
    if len(name) > MAX_MODULE_NAME:
        raise LaneError("MODULE_NAME_TOO_LONG")
    if (
        name.startswith("/")
        or name.startswith("\\\\")
        or re.match(r"^[A-Za-z]:", name) is not None
    ):
        raise LaneError("ABSOLUTE_MODULE_NAME")
    if ".." in name.split("/") or ".." in name.split("\\") or name in (".", ".."):
        raise LaneError("TRAVERSAL_MODULE_NAME")
    if re.match(r"^[A-Za-z]:", name) is not None:
        raise LaneError("ABSOLUTE_MODULE_NAME")
    if "/" in name or "\\" in name:
        raise LaneError("SEPARATOR_MODULE_NAME")
    if any(char in _SHELL_CHARS for char in name):
        raise LaneError("SHELL_INJECTION_MODULE_NAME")
    if os.path.basename(name) != name or os.path.dirname(name) != "":
        raise LaneError("SEPARATOR_MODULE_NAME")
    if _NAME_RE.fullmatch(name) is None:
        raise LaneError("INVALID_MODULE_NAME")
    return name


def resolve_module(registry: Mapping[str, Mapping[str, Any]], name: object) -> Mapping[str, Any]:
    """Resolve one module name through the registry only.

    Name validation runs before membership lookup, and both run before
    any command construction or execution.
    """
    checked = check_module_name(name)
    if type(registry) is not dict or checked not in registry:
        raise LaneError("UNKNOWN_MODULE")
    entry = registry[checked]
    if type(entry) is not dict:
        raise LaneError("MALFORMED_REGISTRY_ENTRY")
    return entry


def _bounded_text(value: object, field: str) -> str:
    if type(value) is not str or not value or len(value) > MAX_TEXT_FIELD:
        raise LaneError(f"INVALID_{field}")
    if any(char.isspace() and char not in (" ",) or ord(char) < 32 for char in value):
        raise LaneError(f"INVALID_{field}")
    return value


def load_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Load a caller-supplied registry JSON file with strict shape checks.

    The file itself is not authority; its provenance must be an accepted
    source (see module docstring). Unknown top-level keys are rejected so
    a second semantic registry cannot hide beside the module map.
    """
    try:
        if path.is_symlink():
            raise LaneError("REGISTRY_NOT_REGULAR")
        raw = path.read_bytes()
    except LaneError:
        raise
    except OSError:
        raise LaneError("REGISTRY_UNAVAILABLE") from None
    if len(raw) > MAX_REGISTRY_BYTES:
        raise LaneError("REGISTRY_SIZE_LIMIT")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise LaneError("MALFORMED_REGISTRY") from None
    if type(data) is not dict or set(data) - {"_provenance", "modules"}:
        raise LaneError("MALFORMED_REGISTRY")
    modules = data.get("modules")
    if type(modules) is not dict or not modules or len(modules) > 64:
        raise LaneError("MALFORMED_REGISTRY")
    for key, entry in modules.items():
        check_module_name(key)
        if type(entry) is not dict:
            raise LaneError("MALFORMED_REGISTRY_ENTRY")
    return modules  # type: ignore[return-value]


@dataclass(frozen=True)
class FrozenBinding:
    module: str
    manifest_relpath: str
    manifest_sha256: str
    manifest_bytes: int
    world: str
    package_id: str
    abi_revision: int
    interface: str
    domain_operation: str
    capsule_operation: str
    capsule_stage: str
    capsule_oracle: str
    native_contract: str
    native_revision: str
    engine_implementation: str
    engine_version: str
    profile: str
    features: tuple[str, ...]

    @property
    def digest(self) -> str:
        payload = {"schema": SCHEMA, **asdict(self)}
        payload["features"] = list(self.features)
        return _digest(payload)


def _read_exact_file(root: Path, relpath: str, limit: int, kind: str) -> bytes:
    if not relpath or relpath.startswith("/") or ".." in Path(relpath).parts:
        raise LaneError(f"{kind}_PATH_REJECTED")
    path = root / relpath
    try:
        if path.is_symlink():
            raise LaneError(f"{kind}_NOT_REGULAR")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise LaneError(f"{kind}_NOT_REGULAR")
            raw = stream.read(limit + 1)
    except LaneError:
        raise
    except OSError:
        raise LaneError(f"{kind}_UNAVAILABLE") from None
    if len(raw) > limit:
        raise LaneError(f"{kind}_SIZE_LIMIT")
    if not raw:
        raise LaneError(f"{kind}_EMPTY")
    return raw


def freeze_module(root: Path, module: str, entry: Mapping[str, Any]) -> FrozenBinding:
    """Freeze manifest/world/capsule binding BEFORE any command runs.

    Reads the exact component manifest bytes, binds their SHA-256, and
    checks the declared world/package/ABI/capsule/engine against the
    frozen accepted constants. Mirrors the ``ModuleContractKit`` /
    ``ModuleTestCapsule`` pre-invocation checks (``capsule.rs``):
    unknown package, legacy world, wrong ABI revision, or a capsule
    operation other than the declared domain operation fails here.
    """
    manifest_rel = entry.get("manifest")
    if type(manifest_rel) is not str:
        raise LaneError("MANIFEST_PATH_REJECTED")
    raw = _read_exact_file(root, manifest_rel, MAX_MANIFEST_BYTES, "MANIFEST")
    try:
        manifest = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise LaneError("MALFORMED_MANIFEST") from None
    package = manifest.get("package") if type(manifest) is dict else None
    if type(package) is not dict or package.get("name") != module:
        raise LaneError("MANIFEST_MODULE_MISMATCH")

    world = _bounded_text(entry.get("world"), "WORLD")
    package_id = _bounded_text(entry.get("package_id"), "PACKAGE")
    if package_id == LEGACY_PACKAGE_ID or world in LEGACY_WORLDS:
        raise LaneError("LEGACY_WORLD_REJECTED")
    if package_id != TYPED_PACKAGE_ID:
        raise LaneError("PACKAGE_MISMATCH")
    if world not in FROZEN_WORLDS:
        raise LaneError("UNKNOWN_WORLD")
    if entry.get("abi_revision") != TYPED_ABI_REVISION:
        raise LaneError("ABI_MISMATCH")
    interface = _bounded_text(entry.get("interface"), "INTERFACE")
    domain_operation = _bounded_text(entry.get("domain_operation"), "OPERATION")

    capsule = entry.get("capsule")
    if type(capsule) is not dict:
        raise LaneError("INVALID_CAPSULE")
    capsule_operation = _bounded_text(capsule.get("operation"), "CAPSULE_OPERATION")
    if capsule_operation != domain_operation:
        raise LaneError("CAPSULE_OPERATION_MISMATCH")
    capsule_stage = _bounded_text(capsule.get("stage"), "CAPSULE_STAGE")
    if capsule_stage not in FROZEN_STAGES:
        raise LaneError("CAPSULE_STAGE_UNKNOWN")
    capsule_oracle = _bounded_text(capsule.get("oracle"), "CAPSULE_ORACLE")
    for bound_key in ("max_input_bytes", "max_output_bytes", "max_work"):
        bound = capsule.get(bound_key)
        if type(bound) is not int or bound <= 0 or bound > 1_073_741_824:
            raise LaneError("CAPSULE_BOUND_INVALID")

    native_contract = _bounded_text(entry.get("native_contract"), "NATIVE_CONTRACT")
    native_revision = _bounded_text(entry.get("native_revision"), "NATIVE_REVISION")
    engine = entry.get("engine")
    if type(engine) is not dict:
        raise LaneError("INVALID_ENGINE")
    engine_implementation = _bounded_text(engine.get("implementation_id"), "ENGINE")
    engine_version = _bounded_text(engine.get("exact_version"), "ENGINE_VERSION")
    if engine_implementation != TYPED_ENGINE_IMPLEMENTATION:
        raise LaneError("ENGINE_MISMATCH")
    if engine_version != TYPED_ENGINE_VERSION:
        raise LaneError("ENGINE_MISMATCH")
    profile = _bounded_text(entry.get("profile", "dev"), "PROFILE")
    features = entry.get("features", [])
    if type(features) is not list or len(features) > 32:
        raise LaneError("INVALID_FEATURES")
    for feature in features:
        _bounded_text(feature, "FEATURE")
    if len(set(features)) != len(features):
        raise LaneError("DUPLICATE_FEATURES")

    return FrozenBinding(
        module=module,
        manifest_relpath=manifest_rel,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        manifest_bytes=len(raw),
        world=world,
        package_id=package_id,
        abi_revision=TYPED_ABI_REVISION,
        interface=interface,
        domain_operation=domain_operation,
        capsule_operation=capsule_operation,
        capsule_stage=capsule_stage,
        capsule_oracle=capsule_oracle,
        native_contract=native_contract,
        native_revision=native_revision,
        engine_implementation=engine_implementation,
        engine_version=engine_version,
        profile=profile,
        features=tuple(sorted(features)),
    )


def cache_identity(
    frozen: FrozenBinding,
    *,
    toolchain: str = TOOLCHAIN_CHANNEL,
    target: str = GUEST_TARGET,
    wit_digest: str,
    dependency_digest: str,
    source_digest: str,
) -> str:
    """Derive the cache identity over the full invalidation closure.

    Any toolchain, target, WIT+ABI, native-contract, dependency,
    profile/feature, or source change alters the identity (cases 7-10).
    A cache hit is an optimization only: it never skips verification.
    """
    if toolchain != TOOLCHAIN_CHANNEL:
        raise LaneError("TOOLCHAIN_NOT_PINNED")
    if target != GUEST_TARGET:
        raise LaneError("TARGET_NOT_PINNED")
    for label, value in (
        ("WIT_DIGEST", wit_digest),
        ("DEPENDENCY_DIGEST", dependency_digest),
        ("SOURCE_DIGEST", source_digest),
    ):
        if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise LaneError(f"INVALID_{label}")
    return _digest({
        "schema": SCHEMA,
        "kind": "cache-identity",
        "toolchain": toolchain,
        "target": target,
        "wit_digest": wit_digest,
        "abi_revision": frozen.abi_revision,
        "package_id": frozen.package_id,
        "world": frozen.world,
        "native_contract": frozen.native_contract,
        "native_revision": frozen.native_revision,
        "manifest_sha256": frozen.manifest_sha256,
        "profile": frozen.profile,
        "features": list(frozen.features),
        "engine": [frozen.engine_implementation, frozen.engine_version],
        "dependency_digest": dependency_digest,
        "source_digest": source_digest,
    })


CACHE_RECORD_SCHEMA = "eliot-wasm-component-lane-cache-v1"
MAX_CACHE_RECORD_BYTES = 65_536


def component_artifact_path(frozen: FrozenBinding, target_root: Path) -> Path:
    """Exact component artifact that build_argv() produces under the isolated lane root.

    ``dev`` lands in ``debug`` and ``release`` in ``release`` beneath the
    lane target root; no other profile is addressable here, and the
    workspace ``target/`` directory is never a fallback.
    """
    module = check_module_name(frozen.module)
    if frozen.profile == "dev":
        profile_dir = "debug"
    elif frozen.profile == "release":
        profile_dir = frozen.profile
    else:
        raise LaneError("INVALID_PROFILE")
    return target_root / GUEST_TARGET / profile_dir / f"{module}.wasm"


def cache_store_root(controller_root: Path, cache_id: str) -> Path:
    """Bounded per-lane cache store directory for one exact cache identity.

    One directory per ``cache_identity()`` digest beneath the controller
    allocated root: never the workspace ``target/`` directory and never a
    lane target root, so incompatible active lanes cannot share it (I2.22).
    """
    if type(cache_id) is not str or re.fullmatch(r"[0-9a-f]{64}", cache_id) is None:
        raise LaneError("INVALID_CACHE_IDENTITY")
    if "target" in controller_root.parts:
        raise LaneError("WORKSPACE_TARGET_REUSE_DENIED")
    return controller_root / f"cache-{cache_id}"


def read_cache_record(controller_root: Path, cache_id: str) -> dict[str, Any] | None:
    """Return the recorded entry whose stored cache_identity equals cache_id, else None on a miss.

    Every unusable cache state is a miss, never an error: absent,
    unreadable, oversized, malformed, foreign schema, foreign identity, or
    an artifact whose recorded ``path``/``sha256``/``bytes`` no longer match
    the bytes on disk. A hit carries artifact lineage only and never a
    stored test or verifier verdict (I2.22).
    """
    if type(cache_id) is not str or re.fullmatch(r"[0-9a-f]{64}", cache_id) is None:
        raise LaneError("INVALID_CACHE_IDENTITY")
    store = cache_store_root(controller_root, cache_id)
    record_path = store / "record.json"
    if store.is_symlink() or record_path.is_symlink():
        return None
    try:
        raw = record_path.read_bytes()
    except OSError:
        return None
    if not raw or len(raw) > MAX_CACHE_RECORD_BYTES:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        return None
    if type(data) is not dict or data.get("schema") != CACHE_RECORD_SCHEMA:
        return None
    if data.get("cache_identity") != cache_id:
        return None
    artifact = data.get("artifact")
    if type(artifact) is not dict:
        return None
    location = artifact.get("path")
    if type(location) is not str or not location:
        return None
    path = Path(location)
    if not path.is_absolute() or path.is_symlink():
        return None
    try:
        digest, size = sha256_file(path)
    except (OSError, LaneError):
        return None
    if type(artifact.get("sha256")) is not str or type(artifact.get("bytes")) is not int:
        return None
    if artifact["sha256"] != digest or artifact["bytes"] != size:
        return None
    return data


def write_cache_record(
    controller_root: Path, cache_id: str, record: Mapping[str, Any]
) -> None:
    """Record one verified artifact under its exact cache identity.

    Canonical JSON lands through one atomic replace inside the bounded
    ``cache_store_root(...)`` directory. A record is accepted only when it
    binds that identity plus its module, artifact, and source; a rejected
    record never becomes cache authority.
    """
    if type(cache_id) is not str or re.fullmatch(r"[0-9a-f]{64}", cache_id) is None:
        raise LaneError("INVALID_CACHE_IDENTITY")
    if type(record) is not dict:
        raise LaneError("MALFORMED_CACHE_RECORD")
    if record.get("cache_identity") != cache_id:
        raise LaneError("CACHE_IDENTITY_MISMATCH")
    for key in ("module", "artifact", "source"):
        if record.get(key) is None:
            raise LaneError("MALFORMED_CACHE_RECORD")
    check_module_name(record["module"])
    payload = dict(record)
    payload["schema"] = CACHE_RECORD_SCHEMA
    try:
        blob = _canonical(payload)
    except (TypeError, ValueError):
        raise LaneError("MALFORMED_CACHE_RECORD") from None
    if len(blob) > MAX_CACHE_RECORD_BYTES:
        raise LaneError("CACHE_RECORD_SIZE_LIMIT")
    store = cache_store_root(controller_root, cache_id)
    if store.is_symlink():
        raise LaneError("CACHE_ROOT_NOT_REGULAR")
    try:
        store.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise LaneError("CACHE_STORE_UNAVAILABLE") from None
    staged: str | None = None
    try:
        descriptor, staged = tempfile.mkstemp(dir=store, prefix=".record-", suffix=".tmp")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(blob)
        os.replace(staged, store / "record.json")
    except OSError:
        if staged is not None:
            try:
                os.unlink(staged)
            except OSError:
                pass
        raise LaneError("CACHE_RECORD_WRITE_FAILED") from None


def lane_target_root(
    controller_root: Path,
    repo_root: Path,
    *,
    toolchain: str = TOOLCHAIN_CHANNEL,
    target: str = GUEST_TARGET,
    wit_digest: str,
    abi_revision: int = TYPED_ABI_REVISION,
    native_contract: str,
    native_revision: str,
    profile: str,
    features_digest: str,
    source_digest: str,
) -> Path:
    """Derive the isolated lane target root allocated by the controller.

    Keyed by toolchain/target, WIT+ABI, native contract, and
    profile/feature/source identity (I2.22). Never the workspace
    ``target/`` directory and never shared by incompatible active lanes.
    """
    if toolchain != TOOLCHAIN_CHANNEL or target != GUEST_TARGET:
        raise LaneError("LANE_IDENTITY_NOT_PINNED")
    if abi_revision != TYPED_ABI_REVISION:
        raise LaneError("ABI_MISMATCH")

    def component(value: str, field: str, max_len: int = 64) -> str:
        if type(value) is not str or not value or len(value) > max_len:
            raise LaneError(f"INVALID_{field}")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is None:
            raise LaneError(f"INVALID_{field}")
        if value in (".", ".."):
            raise LaneError(f"INVALID_{field}")
        return value

    for label, value in (
        ("WIT_DIGEST", wit_digest),
        ("FEATURES_DIGEST", features_digest),
        ("SOURCE_DIGEST", source_digest),
    ):
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{16,64}", value) is None:
            raise LaneError(f"INVALID_{label}")
    short_wit = wit_digest[:16]
    short_features = features_digest[:16]
    short_source = source_digest[:16]
    leaf = (
        f"{toolchain}+{target}"
        f"__wit-{short_wit}+abi{abi_revision}"
        f"__native-{component(native_contract, 'NATIVE_CONTRACT')}"
        f"+{component(native_revision, 'NATIVE_REVISION')}"
        f"__{component(profile, 'PROFILE')}"
        f"+feat-{short_features}"
        f"__src-{short_source}"
    )
    root = controller_root / leaf
    workspace_target = repo_root / "target"
    if root == workspace_target or workspace_target in root.parents:
        raise LaneError("WORKSPACE_TARGET_REUSE_DENIED")
    if root == repo_root or repo_root in root.parents:
        raise LaneError("WORKSPACE_TARGET_REUSE_DENIED")
    return root


def _assert_exact_manifest_argv(argv: Sequence[str], module: str) -> None:
    joined = "\0".join(argv)
    for forbidden in ("--workspace", "--all", "--exclude", "--manifest-path="):
        if forbidden in joined:
            raise LaneError("WORKSPACE_LANE_DENIED")
    if argv[:3] != ["cargo", "build", "-p"] and argv[:3] != ["cargo", "test", "-p"]:
        raise LaneError("NONEXACT_MANIFEST_ARGV")
    if module not in argv:
        raise LaneError("NONEXACT_MANIFEST_ARGV")


def build_argv(frozen: FrozenBinding, target_root: Path) -> list[str]:
    """Fixed exact-manifest build argv for one component.

    Never ``cargo --workspace`` and never the normal workspace lane:
    exactly ``cargo build -p <module> --target <guest>`` under the
    isolated lane root.
    """
    check_module_name(frozen.module)
    argv = [
        "cargo", "build", "-p", frozen.module,
        "--target", GUEST_TARGET,
        "--target-dir", str(target_root),
    ]
    if frozen.profile != "dev":
        argv += ["--profile", frozen.profile]
    for feature in frozen.features:
        argv += ["--features", feature]
    _assert_exact_manifest_argv(argv, frozen.module)
    return argv


def test_argv(frozen: FrozenBinding, target_root: Path) -> list[str]:
    """Fixed declared-capsule-only test argv for one component.

    Executes only the declared capsule stage through the owning package
    test entrypoint (accepted #760/#758 capsule execution path), never
    the workspace gate (#750 remains its owner).
    """
    check_module_name(frozen.module)
    argv = [
        "cargo", "test", "-p", frozen.module,
        "--target", GUEST_TARGET,
        "--target-dir", str(target_root),
        "--", frozen.capsule_stage,
    ]
    _assert_exact_manifest_argv(argv, frozen.module)
    return argv


@dataclass(frozen=True)
class CommandResult:
    status: str
    output: bytes = b""
    cleanup_known: bool = True


def _run(argv: Sequence[str], cwd: Path, timeout: float = COMMAND_TIMEOUT) -> CommandResult:
    """Private fixed-tool runner seam, not a caller-controlled shell.

    Fixed argv only (no shell), scrubbed toolchain-override environment,
    bounded capture. Callers inject a fake in tests; production passes
    only argv built by ``build_argv``/``test_argv``.
    """
    if not argv or any(type(part) is not str for part in argv):
        return CommandResult("ARGV_REJECTED")
    if argv[0] not in ("cargo", "rustc"):
        return CommandResult("TOOL_DENIED")
    env = os.environ.copy()
    env["RUSTUP_AUTO_INSTALL"] = "0"
    for name in ("RUSTUP_TOOLCHAIN", "RUSTUP_TRACE_DIR", "RUSTUP_LOG",
                 "RUSTC_BOOTSTRAP", "RUSTFLAGS", "RUSTC_WRAPPER",
                 "CARGO_NET_GIT_FETCH_WITH_CLI"):
        env.pop(name, None)
    try:
        process = subprocess.Popen(
            list(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
    except OSError:
        return CommandResult("TOOL_UNAVAILABLE")
    output = bytearray()
    overflow = threading.Event()

    def collect() -> None:
        assert process.stdout is not None
        try:
            while chunk := process.stdout.read(4096):
                remaining = MAX_TOOL_OUTPUT - len(output)
                output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
                    process.kill()
                    break
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=collect, daemon=True)
    try:
        reader.start()
    except RuntimeError:
        process.kill()
        return CommandResult("TOOL_READER_UNAVAILABLE", cleanup_known=False)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        return CommandResult("TOOL_TIMEOUT", cleanup_known=False)
    except (OSError, KeyboardInterrupt):
        process.kill()
        return CommandResult("TOOL_CANCELLED", cleanup_known=False)
    reader.join(timeout=5)
    if process.stdout is not None:
        process.stdout.close()
    if overflow.is_set():
        return CommandResult("TOOL_OUTPUT_LIMIT", cleanup_known=False)
    return CommandResult("OK" if process.returncode == 0 else "TOOL_FAILED", bytes(output))


def sha256_file(path: Path, limit: int = 64 * 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > limit:
                raise LaneError("ARTIFACT_SIZE_LIMIT")
            digest.update(chunk)
    return digest.hexdigest(), size


def make_receipt(
    *,
    frozen: FrozenBinding,
    base_sha: str,
    head_sha: str,
    artifact: Mapping[str, Any] | None,
    capsule_report: Mapping[str, Any] | None,
    disposition: str,
    cache_id: str,
    cache_hit: bool,
    argv_digest: str,
) -> dict[str, Any]:
    """Bind one SHA-256-addressed lane receipt.

    Build/test/no-work/skipped/unavailable/cancelled/failed are distinct
    dispositions; missing expected execution is non-green by construction
    (callers must pass FAILED/UNAVAILABLE, never a pass).
    """
    if disposition not in _DISPOSITIONS:
        raise LaneError("INVALID_DISPOSITION")
    for label, value in (("BASE_SHA", base_sha), ("HEAD_SHA", head_sha)):
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise LaneError(f"INVALID_{label}")
    if type(cache_id) is not str or re.fullmatch(r"[0-9a-f]{64}", cache_id) is None:
        raise LaneError("INVALID_CACHE_IDENTITY")
    if type(argv_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", argv_digest) is None:
        raise LaneError("INVALID_ARGV_DIGEST")
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "module": frozen.module,
        "manifest_sha256": frozen.manifest_sha256,
        "manifest_bytes": frozen.manifest_bytes,
        "world": frozen.world,
        "package_id": frozen.package_id,
        "abi_revision": frozen.abi_revision,
        "interface": frozen.interface,
        "native_contract": frozen.native_contract,
        "native_revision": frozen.native_revision,
        "toolchain": TOOLCHAIN_CHANNEL,
        "target": GUEST_TARGET,
        "profile": frozen.profile,
        "features": list(frozen.features),
        "engine": {
            "implementation_id": frozen.engine_implementation,
            "exact_version": frozen.engine_version,
        },
        "source": {"base": base_sha, "head": head_sha},
        "artifact": dict(artifact) if artifact is not None else None,
        "capsule": {
            "operation": frozen.capsule_operation,
            "stage": frozen.capsule_stage,
            "oracle": frozen.capsule_oracle,
            "report": dict(capsule_report) if capsule_report is not None else None,
        },
        "execution": {
            "argv_sha256": argv_digest,
            "disposition": disposition,
            "cache_identity": cache_id,
            "cache_hit": bool(cache_hit),
            "cache_skipped_verification": False,
        },
        "timing": {"cold_s": "UNAVAILABLE", "warm_s": "UNAVAILABLE", "baseline_s": "UNAVAILABLE"},
        "proof_ceiling": "ISOLATED_COMPONENT_EVIDENCE_ONLY",
    }
    return receipt


def bind_observations(
    receipt: dict[str, Any],
    *,
    cold_s: float | None,
    warm_s: float | None,
    baseline_s: float | None = None,
    baseline_provenance: str | None = None,
) -> dict[str, Any]:
    """Attach measured cold/warm timing without fabricated speedup.

    Missing or noncomparable baselines stay explicitly UNAVAILABLE; no
    guessed speedup, threshold, or extra workspace run from this leaf.
    """
    timing = receipt.get("timing")
    if type(timing) is not dict:
        raise LaneError("INVALID_RECEIPT")
    for key, value in (("cold_s", cold_s), ("warm_s", warm_s)):
        if value is None:
            timing[key] = "UNAVAILABLE"
        elif type(value) in (int, float) and value >= 0 and value < 1_000_000:
            timing[key] = float(value)
        else:
            raise LaneError("INVALID_TIMING")
    if baseline_s is None or baseline_provenance is None:
        timing["baseline_s"] = "UNAVAILABLE"
        timing.pop("speedup", None)
    elif (
        type(baseline_s) in (int, float)
        and baseline_s > 0
        and type(baseline_provenance) is str
        and baseline_provenance
        and len(baseline_provenance) <= MAX_TEXT_FIELD
        and type(timing.get("warm_s")) is float
    ):
        timing["baseline_s"] = float(baseline_s)
        timing["baseline_provenance"] = baseline_provenance
        timing["speedup"] = float(baseline_s) / float(timing["warm_s"]) if float(timing["warm_s"]) > 0 else "UNAVAILABLE"
    else:
        raise LaneError("INVALID_BASELINE")
    return receipt


@dataclass(frozen=True)
class Selection:
    selected: tuple[str, ...]
    disposition: str  # SELECTED or NO_WORK
    reason: str


def select_affected(
    registry: Mapping[str, Mapping[str, Any]],
    changed_paths: Sequence[str],
    *,
    shared_prefixes: Sequence[str],
    native_contract_prefixes: Mapping[str, Sequence[str]],
    unrelated_prefixes: Sequence[str],
    dependents: Mapping[str, Sequence[str]] | None = None,
) -> Selection:
    """Compute the affected set from exact base/head evidence.

    - Shared WIT/Host/runtime change selects every registered module.
    - Guest change selects that guest plus registered dependents.
    - Native-contract change selects its registered guest dependents.
    - Known-unrelated change is explicit no-work, never fabricated work.
    - Unknown changed paths or incomplete graph evidence fail closed to
      every registered module; they can never hide a required dependent.
    """
    if type(registry) is not dict or not registry:
        raise LaneError("EMPTY_REGISTRY")
    modules = sorted(registry)
    if type(changed_paths) not in (list, tuple) or not changed_paths:
        raise LaneError("EMPTY_CHANGESET")

    def under(path: str, prefix: str) -> bool:
        return path == prefix or path.startswith(prefix.rstrip("/") + "/")

    normalized: list[str] = []
    for path in changed_paths:
        if type(path) is not str or not path or len(path) > 1024:
            raise LaneError("MALFORMED_CHANGED_PATH")
        if path.startswith("/") or ".." in Path(path).parts or "\\" in path:
            raise LaneError("MALFORMED_CHANGED_PATH")
        normalized.append(path)

    for path in normalized:
        if any(under(path, prefix) for prefix in shared_prefixes):
            return Selection(tuple(modules), "SELECTED", "SHARED_WIT_HOST_RUNTIME_SELECTS_ALL")

    owned: dict[str, str] = {}
    for module in modules:
        entry = registry[module]
        for prefix in entry.get("owned_paths", []):
            if type(prefix) is str and prefix:
                owned[prefix] = module

    directly: set[str] = set()
    unknown: list[str] = []
    for path in normalized:
        hit = next((module for prefix, module in owned.items() if under(path, prefix)), None)
        if hit is not None:
            directly.add(hit)
            continue
        native_hit = next(
            (contract for contract, prefixes in native_contract_prefixes.items()
             if any(under(path, prefix) for prefix in prefixes)),
            None,
        )
        if native_hit is not None:
            for module in modules:
                if registry[module].get("native_contract") == native_hit:
                    directly.add(module)
            continue
        if any(under(path, prefix) for prefix in unrelated_prefixes):
            continue
        unknown.append(path)
    if unknown:
        return Selection(tuple(modules), "SELECTED", "UNKNOWN_PATH_CLOSED_TO_ALL")
    if not directly:
        return Selection((), "NO_WORK", "UNRELATED_CHANGE_NO_WORK")
    if dependents is None:
        # Without a dependents map the fan-out is incomplete evidence;
        # closing to all registered modules cannot hide a dependent.
        if len(directly) != len(modules):
            return Selection(tuple(modules), "SELECTED", "INCOMPLETE_GRAPH_CLOSED_TO_ALL")
        return Selection(tuple(modules), "SELECTED", "DIRECT_SELECTION")
    selected = set(directly)
    for module in list(directly):
        for dependent in dependents.get(module, []):
            if dependent in registry:
                selected.add(dependent)
    return Selection(tuple(sorted(selected)), "SELECTED", "AFFECTED_WITH_DEPENDENTS")


def _load_json_capped(path: Path, limit: int, kind: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError:
        raise LaneError(f"{kind}_UNAVAILABLE") from None
    if len(raw) > limit:
        raise LaneError(f"{kind}_SIZE_LIMIT")
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise LaneError(f"MALFORMED_{kind}") from None


def self_test() -> None:
    """Two focused offline self-checks for the lane (#764, cases 3-4).

    1. An unknown module name is rejected before any command exists.
    2. A traversal/absolute/separator/shell-injection battery is rejected
       before any command exists.

    These checks are separate from the unit-test matrix, which covers the 19
    offline cases 1-15 and 17-20. Cases 16 and 21 are deferred: both need the
    out-of-scope workflow, and 21 also needs an authorized manual dispatch.
    Neither test surface claims live component or workflow evidence.
    """
    fixture = {"eliot-context-compiler-wasm": {"manifest": "x"}}
    calls: list[list[str]] = []

    def never(argv: Sequence[str], cwd: Path, timeout: float = COMMAND_TIMEOUT) -> CommandResult:
        calls.append(list(argv))
        raise AssertionError("self-test must not execute")

    # 1. Unknown module fails before commands.
    try:
        resolve_module(fixture, "eliot-not-registered-wasm")
    except LaneError as error:
        if str(error) != "UNKNOWN_MODULE":
            raise AssertionError(f"self-test unknown typed {error!r}") from None
    else:
        raise AssertionError("self-test unknown module must fail closed")
    # 2. Injection battery fails before commands.
    battery = [
        "../eliot-context-compiler-wasm",
        "..\\eliot-context-compiler-wasm",
        "/etc/passwd",
        "C:\\Windows\\Temp\\x",
        "crates/smart/eliot-context-compiler-wasm",
        "eliot-context-compiler-wasm;rm -rf /",
        "eliot-context-compiler-wasm|cat",
        "eliot-context-compiler-wasm&test",
        "$(cargo build --workspace)",
        "`cargo build --workspace`",
        "eliot-context-compiler-wasm\ncargo build --workspace",
        "${CARGO_HOME}",
        "eliot-context-compiler-wasm*",
        "",
        "x" * 65,
    ]
    for attempt in battery:
        try:
            resolve_module(fixture, attempt)
        except LaneError:
            continue
        raise AssertionError(f"self-test injection must fail closed: {attempt!r}")
    if calls:
        raise AssertionError("self-test executed a command")
    print("WASM_COMPONENT_LANE_SELF_TEST: PASS (2/2)")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--registry", type=Path, default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--receipt-out", type=Path, default=None)
    parser.add_argument("--base-sha", default="0" * 40)
    parser.add_argument("--head-sha", default="0" * 40)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--build", metavar="MODULE")
    modes.add_argument("--test", metavar="MODULE")
    modes.add_argument("--select", action="store_true")
    parser.add_argument("--changed", type=Path, default=None)
    parser.add_argument("--print-argv", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    payload: dict[str, Any] = {"schema": SCHEMA, "proof_ceiling": "ISOLATED_COMPONENT_EVIDENCE_ONLY"}
    try:
        if args.registry is None:
            raise LaneError("REGISTRY_REQUIRED")
        registry = load_registry(args.registry)
        if args.select:
            if args.changed is None:
                raise LaneError("CHANGESET_REQUIRED")
            evidence = _load_json_capped(args.changed, MAX_REGISTRY_BYTES, "CHANGESET")
            # Controller-supplied frozen graph evidence only: exactly these
            # five keys, never a default and never an implicit empty
            # collection that could hide a required dependent.
            if type(evidence) is not dict or set(evidence) != {
                "paths", "shared_prefixes", "native_contract_prefixes",
                "unrelated_prefixes", "dependents",
            }:
                raise LaneError("CHANGESET_EVIDENCE_MALFORMED")

            def evidence_paths(value: object, *, required: bool) -> list[str]:
                if type(value) is not list or len(value) > 256:
                    raise LaneError("CHANGESET_EVIDENCE_MALFORMED")
                if required and not value:
                    raise LaneError("CHANGESET_EVIDENCE_MALFORMED")
                for item in value:
                    if type(item) is not str or not item or len(item) > 1024:
                        raise LaneError("CHANGESET_EVIDENCE_MALFORMED")
                return list(value)

            def evidence_map(value: object) -> dict[str, list[str]]:
                if type(value) is not dict or len(value) > 64:
                    raise LaneError("CHANGESET_EVIDENCE_MALFORMED")
                mapping: dict[str, list[str]] = {}
                for key in value:
                    if type(key) is not str or not key or len(key) > MAX_TEXT_FIELD:
                        raise LaneError("CHANGESET_EVIDENCE_MALFORMED")
                    mapping[key] = evidence_paths(value[key], required=False)
                return mapping

            selection = select_affected(
                registry, evidence_paths(evidence["paths"], required=True),
                shared_prefixes=evidence_paths(evidence["shared_prefixes"], required=False),
                native_contract_prefixes=evidence_map(evidence["native_contract_prefixes"]),
                unrelated_prefixes=evidence_paths(evidence["unrelated_prefixes"], required=False),
                dependents=evidence_map(evidence["dependents"]),
            )
            # Selection is planning evidence only. Both SELECTED and NO_WORK
            # remain non-green; neither disposition fabricates execution.
            payload.update(
                status="FAIL",
                selected=list(selection.selected), disposition=selection.disposition,
                reason=selection.reason,
            )
        else:
            module = args.build or args.test
            if not module:
                raise LaneError("MODULE_REQUIRED")
            entry = resolve_module(registry, module)
            frozen = freeze_module(args.root, module, entry)
            # "Build only the exact component manifest/dependencies for #870's
            # target": the accepted component manifest is the build authority,
            # so the exact-manifest argv runs in that manifest's own workspace
            # root (a registered guest is not a root-workspace member) and
            # never in the repository root.
            manifest_root = (args.root / frozen.manifest_relpath).parent
            try:
                manifest_root.resolve().relative_to(args.root.resolve())
            except ValueError:
                raise LaneError("MANIFEST_PATH_REJECTED") from None
            depends_on = entry.get("depends_on")
            # dependency identity provenance: the registry entry's own declared
            # module.toml depends_on set (owner #638), never a guessed list.
            if type(depends_on) is not list or len(depends_on) > 64:
                raise LaneError("INVALID_DEPENDENCY_IDENTITY")
            for dependency in depends_on:
                _bounded_text(dependency, "DEPENDENCY")
            wit_digest = _digest({"package": TYPED_PACKAGE_ID, "abi": TYPED_ABI_REVISION})
            source_digest = _digest({"base": args.base_sha, "head": args.head_sha})
            dependency_digest = _digest({"depends_on": sorted(depends_on)})
            cache_id = cache_identity(
                frozen, wit_digest=wit_digest,
                dependency_digest=dependency_digest, source_digest=source_digest,
            )
            controller_root = Path(tempfile.gettempdir()) / "eliot-wasm-lane"
            # A hit reuses only the recorded artifact identity; it never skips
            # the gate below.
            record = read_cache_record(controller_root, cache_id)
            cache_hit = record is not None
            target_root = lane_target_root(
                controller_root, args.root,
                wit_digest=wit_digest, native_contract=frozen.native_contract,
                native_revision=frozen.native_revision, profile=frozen.profile,
                features_digest=_digest(sorted(frozen.features)), source_digest=source_digest,
            )
            lane_argv = build_argv(frozen, target_root) if args.build else test_argv(frozen, target_root)
            artifact: dict[str, Any] | None = None
            capsule_report: dict[str, Any] | None = None
            reason: str | None = None
            cold_s: float | None = None
            warm_s: float | None = None
            if args.print_argv:
                # Constructs and reports the exact argv only: no tool runs, so
                # no component can be claimed green.
                disposition = "SKIPPED"
                tool_status = "SKIPPED"
            else:
                started = time.monotonic()
                result = _run(lane_argv, manifest_root)
                elapsed = time.monotonic() - started
                tool_status = result.status
                if result.status == "OK":
                    disposition = "BUILD_PASS" if args.build else "TEST_PASS"
                elif result.status == "TOOL_UNAVAILABLE":
                    disposition = "UNAVAILABLE"
                elif result.status == "TOOL_CANCELLED":
                    disposition = "CANCELLED"
                else:
                    disposition = "FAILED"
                if disposition == "BUILD_PASS":
                    try:
                        artifact_path = component_artifact_path(frozen, target_root)
                        if artifact_path.is_symlink() or not artifact_path.is_file():
                            raise LaneError("ARTIFACT_NOT_REGULAR")
                        artifact_sha256, artifact_bytes = sha256_file(artifact_path)
                    except (LaneError, OSError):
                        # Missing expected execution is non-green.
                        artifact = None
                        disposition = "UNAVAILABLE"
                        reason = "ARTIFACT_UNAVAILABLE"
                    else:
                        artifact = {
                            "path": str(artifact_path),
                            "sha256": artifact_sha256,
                            "bytes": artifact_bytes,
                        }
                        write_cache_record(controller_root, cache_id, {
                            "schema": CACHE_RECORD_SCHEMA,
                            "cache_identity": cache_id,
                            "module": frozen.module,
                            "artifact": artifact,
                            "source": {"base": args.base_sha, "head": args.head_sha},
                        })
                elif disposition == "TEST_PASS":
                    # Only the observed tool status plus the frozen capsule
                    # identity; no parsed, counted, or invented result.
                    capsule_report = {
                        "operation": frozen.capsule_operation,
                        "stage": frozen.capsule_stage,
                        "oracle": frozen.capsule_oracle,
                        "tool_status": result.status,
                    }
                if cache_hit:
                    warm_s = elapsed
                else:
                    cold_s = elapsed
            receipt = make_receipt(
                frozen=frozen, base_sha=args.base_sha, head_sha=args.head_sha,
                artifact=artifact, capsule_report=capsule_report,
                disposition=disposition, cache_id=cache_id, cache_hit=cache_hit,
                argv_digest=_digest(lane_argv),
            )
            # No workspace gate runs from this leaf (#750 owns it), so the
            # comparable baseline stays explicitly unavailable.
            bind_observations(
                receipt, cold_s=cold_s, warm_s=warm_s,
                baseline_s=None, baseline_provenance=None,
            )
            receipt.update(
                status="PASS" if disposition in ("BUILD_PASS", "TEST_PASS") else "FAIL",
                tool_status=tool_status, target_root=str(target_root),
            )
            if reason is not None:
                receipt["reason"] = reason
            if args.print_argv:
                receipt.update(argv=list(lane_argv), frozen_digest=frozen.digest)
            payload = receipt
    except LaneError as error:
        payload.update(status="FAIL", reason=str(error))
    if args.receipt_out is not None:
        try:
            args.receipt_out.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        except OSError:
            payload.update(status="FAIL", reason="RECEIPT_WRITE_FAILED")
    if args.format == "json":
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        execution = payload.get("execution")
        disposition = payload.get("disposition") or (
            execution.get("disposition") if type(execution) is dict else None
        )
        print(f"WASM_COMPONENT_LANE: {payload.get('status')} "
              f"reason={payload.get('reason', disposition or 'OK')} "
              f"proof={payload['proof_ceiling']}")
        if payload.get("schema") == RECEIPT_SCHEMA:
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if payload.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
