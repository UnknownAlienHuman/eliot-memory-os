#!/usr/bin/env python3
"""Fixed branch-only synthetic Rust linker comparison; never acceptance evidence."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

CEILING = "SYNTHETIC_LINKER_ENVIRONMENT_DIAGNOSTIC_ONLY"
MAX_STREAM_BYTES = 65536
TIMEOUT_SECONDS = 90
SDK_KEYS = frozenset(key.casefold() for key in (
    "LIB", "LIBPATH", "INCLUDE", "VCINSTALLDIR", "VCToolsInstallDir", "VCToolsVersion",
    "VSINSTALLDIR", "VSCMD_ARG_TGT_ARCH", "VSCMD_ARG_HOST_ARCH", "VSCMD_VER",
    "WindowsSdkDir", "WindowsSDKVersion", "WindowsSdkVerBinPath", "WindowsLibPath",
    "UniversalCRTSdkDir", "UCRTVersion", "DevEnvDir", "ExtensionSdkDir", "NETFXSDKDir",
    "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
))
DIAGNOSTIC_LINE = re.compile(
    r"(?i)\b(error|fatal|cannot|could not|not found|invalid|unrecognized|failed|"
    r"extra operand|not recognized|operable|LNK[0-9]{4})\b"
)


def load_inventory(root):
    path = root / "scripts/integration/ignored_test_inventory.py"
    spec = importlib.util.spec_from_file_location("linker_probe_inventory", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("inventory module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def actual_inventory_environment(module, root):
    """Observe the existing owner's projection without launching its command."""
    captured = {}

    def capture(argv, **kwargs):
        captured.update(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    original = subprocess.run
    with patch.object(module.subprocess, "run", side_effect=capture):
        module._run_fixed(root, ("git", "rev-parse", "HEAD"))
    if subprocess.run is not original or not captured:
        raise RuntimeError("environment capture did not restore subprocess boundary")
    return captured


def bounded_run(command, cwd, env, timeout_seconds=TIMEOUT_SECONDS):
    """Retain at most 64KiB per stream; stop only this owned child tree on limits."""
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    overflow = threading.Event()
    buffers = [bytearray(), bytearray()]

    def read(stream, buffer):
        with stream:
            while chunk := stream.read(4096):
                remaining = MAX_STREAM_BYTES - len(buffer)
                buffer.extend(chunk[:max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    break

    threads = [threading.Thread(target=read, args=(stream, buffer), daemon=True)
               for stream, buffer in zip((process.stdout, process.stderr), buffers)]
    for thread in threads:
        thread.start()
    reason = None
    while process.poll() is None:
        if overflow.is_set() or time.monotonic() - started >= timeout_seconds:
            reason = "output_limit" if overflow.is_set() else "timeout"
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
            break
        time.sleep(0.05)
    process.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        reason = "stream_cleanup_unknown"
    if overflow.is_set():
        reason = "output_limit"
    return dict(exit_code=process.returncode, elapsed_seconds=round(time.monotonic()-started, 3),
                limit_or_cleanup=reason), bytes(buffers[0]), bytes(buffers[1])


def diagnostic_projection(raw, redact):
    """Keep diagnostic fields only; never retain rendered source or command notes."""
    output = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except (ValueError, UnicodeError, RecursionError):
            continue
        if not isinstance(item, dict) or not isinstance(item.get("message"), str):
            continue
        row = {"level": item.get("level"), "message": redact(item["message"])[:1024],
               "children": []}
        children = item.get("children", [])
        if not isinstance(children, list):
            children = []
        for child in children[:8]:
            if not isinstance(child, dict) or not isinstance(child.get("message"), str):
                continue
            text = redact(child["message"])
            entry = {"level": child.get("level"), "message_bytes": len(child["message"].encode()),
                     "disposition": "non_diagnostic_or_command_omitted", "diagnostic_lines": []}
            # A quoted executable/argv note is not diagnostic text, even if an
            # argument contains words such as error. Synthetic source has no payload.
            if not text.lstrip().startswith(('"', "'")):
                entry["diagnostic_lines"] = [line[:1024] for line in text.splitlines()
                                             if DIAGNOSTIC_LINE.search(line)][:4]
                if entry["diagnostic_lines"]:
                    entry["disposition"] = "bounded_redacted_diagnostic"
            row["children"].append(entry)
        output.append(row)
        if len(output) == 8:
            break
    return output


def identity_ready(identity):
    return (identity["exit_code"] == 0 and identity["limit_or_cleanup"] is None
            and "host: x86_64-pc-windows-msvc" in identity["version_lines"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if os.name != "nt" or os.environ.get("GITHUB_REF") != "refs/heads/Operator_tests":
        raise RuntimeError("probe requires the admitted Operator_tests Windows runner")
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if sha != os.environ.get("GITHUB_SHA"):
        raise RuntimeError("checked-out source does not match workflow source")
    output = Path(args.output).resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if output == runner_temp or not output.is_relative_to(runner_temp):
        raise RuntimeError("output must be a dedicated child of runner temp")
    output.mkdir(parents=True, exist_ok=True)
    inventory = load_inventory(root)
    filtered = actual_inventory_environment(inventory, root)
    normal = os.environ.copy()
    restored = {key: value for key, value in normal.items()
                if key.casefold() in SDK_KEYS and key not in filtered and len(value) <= 32768}
    record = {"proof_ceiling": CEILING, "source": sha,
              "os_identity": {"system": platform.system(), "release": platform.release(),
                              "version": platform.version(), "machine": platform.machine()},
              "inventory_sha256": hashlib.sha256((root / "scripts/integration/ignored_test_inventory.py").read_bytes()).hexdigest(),
              "whitelist_key_names": sorted(filtered), "restorable_sdk_key_names": sorted(restored),
              "source_text": "fn main() {}\n", "runs": []}
    result_path = output / "result.json"
    try:
        # Rustup can materialize the repository-pinned toolchain here. A failed
        # setup is not a valid normal-versus-whitelist comparison baseline.
        identity, version_out, _ = bounded_run(["rustc", "-vV"], root, normal, 180)
    except (OSError, subprocess.SubprocessError) as error:
        identity = dict(exit_code=None, elapsed_seconds=None,
                        limit_or_cleanup=type(error).__name__)
        version_out = b""
    identity["version_lines"] = [line for line in version_out.decode("utf-8", errors="replace").splitlines()
                                 if line.startswith(("rustc ", "binary:", "commit-hash:", "commit-date:",
                                                     "host:", "release:", "LLVM version:"))]
    record["rustc_identity"] = identity
    result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    if not identity_ready(identity):
        record["comparison"] = "NOT_EXECUTED_TOOLCHAIN_SETUP_UNAVAILABLE"
        result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        print("LINKER_PROBE_SETUP_UNAVAILABLE: no environment comparison executed", flush=True)
        return 1
    with tempfile.TemporaryDirectory(prefix="eliot-linker-probe-", dir=runner_temp) as scratch:
        work = Path(scratch)
        source = work / "main.rs"
        source.write_text(record["source_text"], encoding="utf-8")
        environments = [("normal", normal), ("inventory_whitelist", filtered)]
        for name, env in environments:
            target = work / name
            target.mkdir()
            command = ["rustc", "--crate-name", "eliot_linker_probe", "--edition=2024",
                       "--error-format=json", str(source), "-o", str(target / "probe.exe")]
            try:
                result, stdout, stderr = bounded_run(command, root, env)
            except (OSError, subprocess.SubprocessError) as error:
                result = dict(exit_code=None, elapsed_seconds=None,
                              limit_or_cleanup=type(error).__name__)
                stdout, stderr = b"", b""
            result.update(name=name, command=command, executable_exists=(target / "probe.exe").is_file(),
                          stdout_retained_bytes=len(stdout), stderr_retained_bytes=len(stderr),
                          diagnostics=diagnostic_projection(stderr, inventory._redact_detail))
            record["runs"].append(result)
            result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            print(json.dumps({"probe": name, "exit_code": result["exit_code"],
                              "limit_or_cleanup": result["limit_or_cleanup"]}), flush=True)
            if name == "inventory_whitelist" and restored and record["runs"][0]["exit_code"] == 0 and result["exit_code"] != 0:
                environments.append(("inventory_whitelist_plus_sdk", {**filtered, **restored}))
        record["comparison"] = "direct_synthetic_rustc_linking_normal_vs_inventory_projection_not_cargo_graph_proof"
        record["sdk_restore_attempted"] = len(record["runs"]) == 3
        record["no_product_or_governed_acceptance"] = True
        result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    # A retained negative is useful diagnosis, but remains an explicit failed
    # baseline rather than a green toolchain/acceptance claim.
    return int(any(run["exit_code"] != 0 or run["limit_or_cleanup"] for run in record["runs"]))


if __name__ == "__main__":
    raise SystemExit(main())
