#!/usr/bin/env python3
"""Check the declared WASI component target without installing anything.

Default mode is offline/read-only and proves declaration only. --diagnostic
inspects an already installed toolchain; --probe also compiles a fixed, empty
component in temporary storage. Neither mode qualifies a clean bootstrap,
executes the component, downloads Rust, or proves guest/WIT behavior.

Normative target: docs/architecture/I14-19-wasm-components.md. Refs #870.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import tomllib
from dataclasses import asdict, dataclass
from typing import Sequence

SCHEMA = "eliot-wasm-toolchain-check-v1"
HOST_TARGET = "x86_64-pc-windows-msvc"
GUEST_TARGET = "wasm32-wasip2"
COMPONENTS = frozenset({"clippy", "rustfmt", "rust-analyzer", "rust-src"})
MAX_CONFIG_BYTES = 16_384
MAX_TOOL_OUTPUT = 65_536
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
COMMAND_TIMEOUT = 30.0
PROBE_TIMEOUT = 120.0
PROBE_SOURCE = b"fn main() {}\n"
# WebAssembly Component Model binary header, not a core-module header.
COMPONENT_HEADER = b"\x00asm\x0d\x00\x01\x00"


class ToolchainError(ValueError):
    """A bounded reason code; never includes untrusted TOML or tool output."""


@dataclass(frozen=True)
class Declaration:
    channel: str
    profile: str
    components: tuple[str, ...]
    targets: tuple[str, ...]

    @property
    def digest(self) -> str:
        payload = {"schema": SCHEMA, **asdict(self)}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


def _unique_strings(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not list or not value or len(value) > 16:
        raise ToolchainError(f"INVALID_{field}")
    if any(type(item) is not str or len(item) > 80 for item in value):
        raise ToolchainError(f"INVALID_{field}")
    if len(set(value)) != len(value):
        raise ToolchainError(f"DUPLICATE_{field}")
    return tuple(sorted(value))


def parse_declaration(raw: bytes) -> Declaration:
    if type(raw) is not bytes or len(raw) > MAX_CONFIG_BYTES:
        raise ToolchainError("CONFIG_SIZE_LIMIT")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise ToolchainError("MALFORMED_TOOLCHAIN") from None
    if set(data) != {"toolchain"} or type(data["toolchain"]) is not dict:
        raise ToolchainError("UNKNOWN_TOOLCHAIN_SCHEMA")
    toolchain = data["toolchain"]
    if set(toolchain) != {"channel", "profile", "components", "targets"}:
        raise ToolchainError("UNKNOWN_TOOLCHAIN_FIELDS")
    channel = toolchain["channel"]
    if type(channel) is not str or not re.fullmatch(r"[1-9][0-9]{0,2}\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})", channel):
        raise ToolchainError("CHANNEL_NOT_PINNED")
    # Rust 1.82 introduced the tier-2, rustup-installable wasip2 target.
    if tuple(map(int, channel.split("."))) < (1, 82, 0):
        raise ToolchainError("CHANNEL_PREDATES_WASIP2_TIER2")
    if toolchain["profile"] != "default":
        raise ToolchainError("UNEXPECTED_PROFILE")
    components = _unique_strings(toolchain["components"], "COMPONENTS")
    if set(components) != COMPONENTS:
        raise ToolchainError("UNEXPECTED_COMPONENTS")
    targets = _unique_strings(toolchain["targets"], "TARGETS")
    if HOST_TARGET not in targets:
        raise ToolchainError("HOST_TARGET_MISSING")
    if GUEST_TARGET not in targets:
        raise ToolchainError("GUEST_TARGET_MISSING")
    if set(targets) != {HOST_TARGET, GUEST_TARGET}:
        raise ToolchainError("UNOWNED_TARGET")
    return Declaration(channel, "default", components, targets)


def read_declaration(root: Path) -> Declaration:
    path = root / "rust-toolchain.toml"
    try:
        legacy = root / "rust-toolchain"
        if legacy.exists() or legacy.is_symlink():
            raise ToolchainError("LEGACY_TOOLCHAIN_SHADOWS_TOML")
        if path.is_symlink():
            raise ToolchainError("TOOLCHAIN_NOT_REGULAR")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ToolchainError("TOOLCHAIN_NOT_REGULAR")
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except ToolchainError:
        raise
    except (OSError, ValueError):
        raise ToolchainError("TOOLCHAIN_UNAVAILABLE") from None
    return parse_declaration(raw)


@dataclass(frozen=True)
class CommandResult:
    status: str
    output: bytes = b""
    cleanup_known: bool = True


def _run(argv: Sequence[str], cwd: Path, timeout: float) -> CommandResult:
    """Private fixed-tool diagnostic seam, not a caller-controlled runner.

    Capture is bounded while reading. On abnormal termination, descendants may
    outlive a Windows parent: report cleanup unknown and never certify a probe.
    """
    env = os.environ.copy()
    env["RUSTUP_AUTO_INSTALL"] = "0"
    for name in ("RUSTUP_TOOLCHAIN", "RUSTUP_TRACE_DIR", "RUSTUP_LOG", "RUSTC_LOG",
                 "RUSTC_BOOTSTRAP", "RUSTFLAGS", "RUSTC_WRAPPER"):
        env.pop(name, None)
    try:
        process = subprocess.Popen(
            list(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=(os.name != "nt"),
        )
    except OSError:
        return CommandResult("TOOL_UNAVAILABLE")
    output = bytearray()
    overflow = threading.Event()
    reader_failed = threading.Event()

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
            reader_failed.set()

    def terminate() -> None:
        try:
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass

    reader = threading.Thread(target=collect, daemon=True)
    try:
        reader.start()
    except RuntimeError:
        terminate()
        if process.stdout is not None:
            process.stdout.close()
        return CommandResult("TOOL_READER_UNAVAILABLE", cleanup_known=False)
    failure = None
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        failure = "TOOL_TIMEOUT"
    except KeyboardInterrupt:
        failure = "TOOL_CANCELLED"
    except OSError:
        failure = "TOOL_WAIT_FAILED"
    if failure is not None:
        terminate()
    reader.join(timeout=2)
    if reader.is_alive():
        # Closing a buffered pipe from another thread can block on its read
        # lock. Preserve uncertainty instead of hanging the checker.
        return CommandResult(failure or "TOOL_OUTPUT_INCOMPLETE", cleanup_known=False)
    if process.stdout is not None:
        process.stdout.close()
    if failure is not None:
        return CommandResult(failure, cleanup_known=False)
    if overflow.is_set():
        return CommandResult("TOOL_OUTPUT_LIMIT", cleanup_known=False)
    if reader_failed.is_set():
        return CommandResult("TOOL_OUTPUT_INCOMPLETE", cleanup_known=False)
    return CommandResult("OK" if process.returncode == 0 else "TOOL_FAILED", bytes(output))


def diagnose(declaration: Declaration, *, probe: bool = False) -> dict[str, object]:
    result: dict[str, object] = {
        "status": "INCOMPLETE", "installed": False, "compilable": "NOT_RUN",
        "clean_bootstrap_qualified": False, "reason": "RUSTUP_UNAVAILABLE",
        "proof_ceiling": "DECLARATION_ONLY",
    }
    rustup = shutil.which("rustup")
    if rustup is None:
        return result
    # Even a diagnostic runs outside the repository, so tool overrides,
    # repository build scripts and Cargo configuration cannot enter the probe.
    try:
        scratch = Path(tempfile.mkdtemp(prefix="eliot-wasm-toolchain-"))
    except OSError:
        result["reason"] = "PROBE_IO_FAILED"
        return result
    cleanup_known = True
    try:
        def run(args: Sequence[str], timeout: float = COMMAND_TIMEOUT) -> CommandResult:
            nonlocal cleanup_known
            observed = _run([rustup, *args], scratch, timeout)
            cleanup_known = cleanup_known and observed.cleanup_known
            return observed

        available = run(["toolchain", "list"])
        if available.status != "OK":
            result["reason"] = available.status
            return result
        toolchains = [line.split()[0] for line in available.output.decode("utf-8", "replace").splitlines() if line.split()]
        if not any(name == declaration.channel or name.startswith(declaration.channel + "-") for name in toolchains):
            result["reason"] = "PINNED_TOOLCHAIN_NOT_INSTALLED"
            return result
        version = run(["run", declaration.channel, "rustc", "--version", "--verbose"])
        if version.status != "OK":
            result["reason"] = version.status
            return result
        fields = dict(
            line.split(": ", 1) for line in version.output.decode("utf-8", "replace").splitlines()
            if ": " in line
        )
        if fields.get("release") != declaration.channel:
            result["reason"] = "COMPILER_VERSION_MISMATCH"
            return result
        commit = fields.get("commit-hash", "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            result["reason"] = "COMPILER_IDENTITY_MISSING"
            return result
        result["compiler_commit"] = commit
        installed = run(["target", "list", "--installed", "--toolchain", declaration.channel])
        if installed.status != "OK":
            result["reason"] = installed.status
            return result
        observed_targets = set(installed.output.decode("utf-8", "replace").splitlines())
        missing = sorted(set(declaration.targets) - observed_targets)
        if missing:
            result.update(reason="DECLARED_TARGET_NOT_INSTALLED", missing_targets=missing)
            return result
        result.update(installed=True, proof_ceiling="INSTALLED_TOOLCHAIN_ONLY")
        if not probe:
            result.update(status="PASS", reason="INSTALLED_NOT_COMPILED")
            return result
        source = scratch / "probe.rs"
        artifact = scratch / "probe.wasm"
        source.write_bytes(PROBE_SOURCE)
        compiled = run([
            "run", declaration.channel, "rustc", "--edition=2021",
            "--crate-name", "eliot_wasm_toolchain_probe", "--crate-type=bin",
            "--target", GUEST_TARGET, str(source), "-o", str(artifact),
        ], PROBE_TIMEOUT)
        if compiled.status != "OK":
            result.update(reason=compiled.status, compilable=False)
            return result
        try:
            with artifact.open("rb") as stream:
                raw = stream.read(MAX_ARTIFACT_BYTES + 1)
        except OSError:
            result.update(reason="COMPILE_ARTIFACT_MISSING", compilable=False)
            return result
        if len(raw) > MAX_ARTIFACT_BYTES or not raw.startswith(COMPONENT_HEADER):
            result.update(reason="COMPILE_ARTIFACT_INVALID", compilable=False)
            return result
        result.update(
            status="PASS", reason="LOCAL_COMPONENT_COMPILED", compilable=True,
            proof_ceiling="LOCAL_COMPONENT_COMPILE_ONLY",
            probe_sha256=hashlib.sha256(PROBE_SOURCE).hexdigest(),
            artifact_sha256=hashlib.sha256(raw).hexdigest(), artifact_bytes=len(raw),
        )
        return result
    except OSError:
        result.update(status="INCOMPLETE", reason="PROBE_IO_FAILED")
        return result
    finally:
        if cleanup_known:
            try:
                shutil.rmtree(scratch)
            except OSError:
                cleanup_known = False
        if not cleanup_known:
            if result["status"] == "PASS":
                result["reason"] = "CLEANUP_FAILED"
            result.update(status="INCOMPLETE", cleanup="UNKNOWN", scratch_retained=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--format", choices=("text", "json"), default="text")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--diagnostic", action="store_true")
    modes.add_argument("--probe", action="store_true")
    args = parser.parse_args(argv)
    payload: dict[str, object] = {"schema": SCHEMA, "proof_ceiling": "DECLARATION_ONLY"}
    try:
        declaration = read_declaration(args.root)
        payload.update(status="PASS", reason="DECLARED_NOT_EXECUTED",
                       declaration=asdict(declaration), declaration_sha256=declaration.digest,
                       installed="NOT_CHECKED", compilable="NOT_RUN",
                       clean_bootstrap_qualified=False)
        if args.diagnostic or args.probe:
            payload.update(diagnose(declaration, probe=args.probe))
    except ToolchainError as error:
        payload.update(status="FAIL", reason=str(error))
    if args.format == "json":
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(f"WASM_TOOLCHAIN: {payload['status']} reason={payload['reason']} "
              f"proof={payload['proof_ceiling']}")
    return 0 if payload["status"] == "PASS" else (1 if payload["status"] == "FAIL" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
