#!/usr/bin/env python3
"""Branch-only diagnostic commands, never Review/MergeCompile/Product acceptance.

Explicit audit opt-in only. Native Windows dev/test profiles, no CARGO_FEATURE_PURE,
no release build, no installation, no ignored tests, no provider credentials.
The transparent plan and every exit/timeout/skip are retained outside Git.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time

CEILING = "OPERATOR_AUDIT_DIAGNOSTIC_ONLY_NOT_GOVERNED_ACCEPTANCE"
# Independently observed compile failures at f4d32c0. These packages are still
# attempted one by one, not silently excluded from the diagnostic denominator.
COMPILE_BLOCKED = (
    "eliot-dreamer", "eliot-agent-bridge", "eliot-researcher", "eliot",
    "eliot-installation", "eliot-store-surreal", "eliotd", "eliot-host",
    "eliot-kernel", "eliot-runtime-status",
)


def stage(name, command, minutes=10, *, tests=False, expected_exit=0,
          stdin=None, contains=None, prerequisite=None):
    return dict(name=name, command=list(command), timeout_seconds=minutes * 60,
                tests=tests, expected_exit=expected_exit, stdin=stdin,
                contains=contains, prerequisite=prerequisite)


def plan(root, output, target, *, runtime_edges_only=False):
    cargo_test = ["cargo", "test", "--locked", "--no-fail-fast"]
    if runtime_edges_only:
        return [
            stage("rustc-identity", ["rustc", "-vV"], 3, contains="host: x86_64-pc-windows-msvc"),
            stage("cargo-identity", ["cargo", "--version"], 3),
            stage("metadata", ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], 3),
            stage("runtime-production-build-dev", ["cargo", "build", "--locked", "-p", "eliot-kernel", "-p", "eliot-wasm-host", "--lib", "--bins"], 20),
            stage("kernel-shutdown-durability", cargo_test + ["-p", "eliot-kernel", "--lib", "shutdown_drain::shutdown_drain_tests"] + ["--", "--nocapture", "--test-threads=1"], 8, tests=True),
            stage("kernel-running-hot-spine", cargo_test + ["-p", "eliot-kernel", "--lib", "hot_path_runtime::tests"] + ["--", "--nocapture", "--test-threads=1"], 3, tests=True),
            stage("wasm-admitted-process-edge", cargo_test + ["-p", "eliot-wasm-host", "--test", "admitted_execution"] + ["--", "--nocapture", "--test-threads=1"], 8, tests=True),
        ]
    selected = ["--workspace"]
    for package in COMPILE_BLOCKED:
        selected += ["--exclude", package]
    tail = ["--", "--test-threads=1"]
    exe = target / "debug" / "skill_pack_snapshot_verify.exe"
    rows = [
        stage("rustc-identity", ["rustc", "-vV"], 3, contains="host: x86_64-pc-windows-msvc"),
        stage("cargo-identity", ["cargo", "--version"], 3),
        stage("metadata", ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], 3),
        stage("production-build-dev", ["cargo", "build", "--locked", "--workspace", "--lib", "--bins"], 55),
        stage("skill-snapshot-valid", [str(exe)], 1,
              stdin=str(output / "skill-valid.json"),
              contains="eliot.skill-pack-snapshot-result.v1", prerequisite=str(exe)),
        stage("skill-snapshot-corrupt", [str(exe)], 1, expected_exit=1,
              stdin=str(output / "skill-corrupt.json"),
              contains="content_blake3 does not match", prerequisite=str(exe)),
        stage("shipped-hot-path-loader", cargo_test + ["-p", "eliot-runtime-contracts", "--test", "shipped_hot_path"] + tail, 10, tests=True),
        stage("hot-path-queue-binder", cargo_test + ["-p", "eliot-runtime-contracts", "--test", "hot_path_queue_binding"] + tail, 10, tests=True),
        stage("kernel-running-hot-spine", cargo_test + ["-p", "eliot-kernel", "--lib", "hot_path_runtime::tests"] + tail, 10, tests=True),
        # Real redb reopen/guard edge; not installed-daemon restart acceptance.
        stage("ors-redb-durability", cargo_test + ["-p", "eliot-ors", "--test", "doctor_redb"] + tail, 10, tests=True),
        stage("host-journal-queue", cargo_test + ["-p", "eliot-host-state", "--test", "reactive_context_queue"] + tail, 10, tests=True),
        # Exact test launches the shipped Host with an invalid flag; no SCM install.
        stage("host-startup-negative", cargo_test + ["-p", "eliot-host", "--test", "host_console_diagnostics", "host_console_binary_keeps_protocol_on_stdout_only"] + ["--", "--exact", "--test-threads=1"], 10, tests=True),
        stage("kernel-unavailable-negative", cargo_test + ["-p", "eliot-kernel", "--test", "kernel_unavailable_admission"] + tail, 10, tests=True),
        # Isolated Job-contained child/Wasmtime edge; fixture identity, not install.
        stage("wasm-admitted-process-edge", cargo_test + ["-p", "eliot-wasm-host", "--test", "admitted_execution"] + tail, 15, tests=True),
        stage("workspace-tests-except-known-compile-blockers", cargo_test + selected + tail, 55, tests=True),
    ]
    for package in COMPILE_BLOCKED:
        rows.append(stage("isolated-tests-" + package,
                          cargo_test + ["-p", package] + tail, 8, tests=True))
    return rows



BROAD_TEST_STAGE = "workspace-tests-except-known-compile-blockers"
FALLBACK_CONDITION = ("Broad selected workspace compilation failed with nonzero exit and "
                      "no completed or started tests; same members from recorded metadata, "
                      "excluding COMPILE_BLOCKED; run after the existing isolated blockers")


def fallback_required(result, text):
    counts = result.get("test_counts", {})
    executed = sum(counts.get(key, 0) for key in ("passed", "failed"))
    started = re.search(r"(?m)^running [1-9][0-9]* tests?$|^test .+ \.\.\. (?:ok|FAILED)$", text)
    compile_failure = re.search(r"could not compile|error\[E[0-9]+\]|failed to run custom build command|linking with .* failed", text)
    return (result.get("name") == BROAD_TEST_STAGE and result.get("status") == "FAILED"
            and result.get("exit_code") not in (None, 0) and executed == 0
            and started is None and compile_failure is not None)


def fallback_plan(metadata):
    members = set(metadata["workspace_members"])
    packages = [package for package in metadata["packages"] if package["id"] in members]
    if {package["id"] for package in packages} != members:
        raise ValueError("recorded metadata does not describe every selected workspace member")
    names = sorted(package["name"] for package in packages
                   if package["name"] not in COMPILE_BLOCKED)
    if not names or len(names) != len(set(names)):
        raise ValueError("selected workspace package names are empty or ambiguous")
    return [stage("fallback-tests-" + name,
                  ["cargo", "test", "--locked", "--no-fail-fast", "-p", name,
                   "--", "--test-threads=1"], 8, tests=True) for name in names]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def terminate_owned_tree(process):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=20)


def execute(spec, output, cwd, remaining_seconds):
    result = dict(spec, status="NOT_EXECUTED", exit_code=None,
                  elapsed_seconds=0, reason=None)
    if remaining_seconds <= 0:
        return dict(result, status="SKIPPED", reason="global diagnostic time budget exhausted")
    if spec["prerequisite"] and not Path(spec["prerequisite"]).is_file():
        return dict(result, status="SKIPPED", reason="required built executable is missing")
    if shutil.disk_usage(output).free < 2 * 1024 ** 3:
        return dict(result, status="SKIPPED", reason="less than 2 GiB free disk; bounded diagnostic stop")
    stdout_path = output / (spec["name"] + ".stdout.log")
    stderr_path = output / (spec["name"] + ".stderr.log")
    result.update(stdout=str(stdout_path), stderr=str(stderr_path))
    started = time.monotonic()
    print("DIAGNOSTIC_START " + json.dumps(spec), flush=True)
    source = None
    try:
        source = open(spec["stdin"], "rb") if spec["stdin"] else subprocess.DEVNULL
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(spec["command"], cwd=cwd, stdin=source,
                                       stdout=stdout, stderr=stderr,
                                       start_new_session=os.name != "nt")
            deadline = started + min(spec["timeout_seconds"], remaining_seconds)
            while True:
                try:
                    result["exit_code"] = process.wait(timeout=min(30, max(0.01, deadline - time.monotonic())))
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic() >= deadline:
                        terminate_owned_tree(process)
                        result.update(status="TIMED_OUT", exit_code=process.returncode,
                                      reason="owned process tree terminated at diagnostic deadline")
                        break
                    print(f"DIAGNOSTIC_RUNNING {spec['name']} elapsed={int(time.monotonic() - started)}s", flush=True)
        text = stdout_path.read_text(encoding="utf-8", errors="replace") + stderr_path.read_text(encoding="utf-8", errors="replace")
        counts = re.findall(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
        result["test_counts"] = {key: sum(int(row[i]) for row in counts)
                                 for i, key in enumerate(("passed", "failed", "ignored"))}
        if result["status"] != "TIMED_OUT":
            matched = result["exit_code"] == spec["expected_exit"]
            if spec["contains"] and spec["contains"] not in text:
                matched = False
                result["reason"] = "expected output discriminator missing"
            if spec["tests"] and sum(result["test_counts"][key] for key in ("passed", "failed")) == 0:
                matched = False
                result["reason"] = "no executed tests observed (compilation or selection may have failed)"
            result["status"] = "EXPECTED_OUTCOME" if matched else "FAILED"
        print(text[-3000:], flush=True)
    except (OSError, subprocess.SubprocessError) as error:
        result.update(status="FAILED", reason=f"{type(error).__name__}: {error}")
    finally:
        if source not in (None, subprocess.DEVNULL):
            source.close()
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    for key, path in (("stdout_sha256", stdout_path), ("stderr_sha256", stderr_path)):
        if path.exists():
            result[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    print("DIAGNOSTIC_RESULT " + json.dumps(result), flush=True)
    return result


def self_test():
    with tempfile.TemporaryDirectory(prefix="eliot-audit-script-") as directory:
        root = Path(directory)
        ok = execute(stage("positive", [sys.executable, "-c", "print('marker')"], contains="marker"), root, root, 10)
        negative = execute(stage("negative", [sys.executable, "-c", "raise SystemExit(3)"], expected_exit=3), root, root, 10)
        bad = execute(stage("bad", [sys.executable, "-c", "raise SystemExit(2)"]), root, root, 10)
        zero = execute(stage("zero-tests", [sys.executable, "-c", "print('no tests')"], tests=True), root, root, 10)
        timeout = execute(stage("timeout", [sys.executable, "-c", "import time;time.sleep(20)"]), root, root, 0.1)
        skipped = execute(stage("skipped", ["missing"]), root, root, 0)
        assert [row["status"] for row in (ok, negative, bad, zero, timeout, skipped)] == ["EXPECTED_OUTCOME", "EXPECTED_OUTCOME", "FAILED", "FAILED", "TIMED_OUT", "SKIPPED"]
    metadata = {"workspace_members": ["a", "b"], "packages": [
        {"id": "a", "name": "eliot-example"}, {"id": "b", "name": COMPILE_BLOCKED[0]},
        {"id": "external", "name": "not-a-member"}]}
    assert [row["name"] for row in fallback_plan(metadata)] == ["fallback-tests-eliot-example"]
    failed = dict(name=BROAD_TEST_STAGE, status="FAILED", exit_code=101,
                  test_counts={"passed": 0, "failed": 0})
    assert fallback_required(failed, "error[E0599]: absent method")
    assert not fallback_required(failed, "could not compile x\nrunning 1 test")
    assert not fallback_required(failed, "could not compile x\ntest a ... ok")
    assert not fallback_required(dict(failed, test_counts={"passed": 1}), "could not compile x")
    assert not fallback_required(dict(failed, exit_code=0), "could not compile x")
    assert not fallback_required(dict(failed, status="TIMED_OUT"), "could not compile x")
    assert not fallback_required(failed, "failed to download dependency")
    try:
        fallback_plan(dict(metadata, workspace_members=["missing"]))
    except ValueError:
        pass
    else:
        raise AssertionError("incomplete metadata must not reduce the denominator")
    edge_plan = plan(Path("."), Path("."), Path("."), runtime_edges_only=True)
    assert len(edge_plan) == 7
    assert all("--workspace" not in row["command"] for row in edge_plan)
    assert [row["name"] for row in edge_plan if row["tests"]] == ["kernel-shutdown-durability", "kernel-running-hot-spine", "wasm-admitted-process-edge"]
    print("diagnostic runner self-test: 18 passed")


def binary_inventory(target, source_sha, build_status):
    rows = []
    for path in sorted((target / "debug").glob("*.exe")):
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        rows.append(dict(name=path.name, path=str(path), bytes=path.stat().st_size,
                         sha256=digest.hexdigest()))
    return dict(ceiling=CEILING, source_sha=source_sha, build_stage_status=build_status,
                profile="dev unoptimized debug=0; NOT release or installation package",
                target="native x86_64-pc-windows-msvc (see rustc-identity logs)",
                binaries=rows, binary_artifacts_uploaded=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--runtime-edges-only", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.output is None:
        parser.error("--output is required")
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", output / "target")).resolve()
    specs = plan(root, output, target, runtime_edges_only=args.runtime_edges_only)
    write_json(output / "plan.json", dict(ceiling=CEILING, profile="native Windows dev/test; not release", stages=specs, conditional_fallback=dict(
               status="NOT_APPLICABLE" if args.runtime_edges_only else "CONDITIONAL",
               condition=None if args.runtime_edges_only else FALLBACK_CONDITION,
               metadata_source="metadata.stdout.log",
               stages=[] if args.runtime_edges_only else "resolved after metadata stage")))
    if args.plan_only:
        return 0
    if os.name != "nt" or os.environ.get("GITHUB_REF") != "refs/heads/Operator_tests":
        raise RuntimeError("diagnostics require native Windows on refs/heads/Operator_tests")
    if "CARGO_FEATURE_PURE" in os.environ:
        raise RuntimeError("CARGO_FEATURE_PURE is forbidden for this native Windows diagnosis")
    required_environment = {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
                            "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0"}
    if any(os.environ.get(key) != value for key, value in required_environment.items()):
        raise RuntimeError("diagnostic resource/profile environment differs from declared plan")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if head != os.environ.get("GITHUB_SHA"):
        raise RuntimeError("checked-out SHA differs from manually dispatched SHA")
    report = dict(ceiling=CEILING, source_sha=head, source_ref=os.environ["GITHUB_REF"],
                  profile="dev/test, unoptimized, debug=0, incremental=0, jobs=2; NOT release",
                  cargo_environment={key: os.environ.get(key) for key in required_environment},
                  input_sha256={name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                                for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/operator-audit-diagnostic.py")},
                  cargo_feature_pure="UNSET", started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  ignored_tests="not requested", runtime_edges_only=args.runtime_edges_only,
                  stages=[], complete=False)
    write_json(output / "results.json", report)
    skill_root = root / "integrations" / "agent-skills"
    payload = dict(schema_version="eliot.skill-pack-snapshot.v1",
                   manifest_text=(skill_root / "skill-pack.manifest.json").read_text(encoding="utf-8"),
                   skills=[dict(name=name, body_text=(skill_root / name / "SKILL.md").read_text(encoding="utf-8"))
                           for name in ("eliot-work", "eliot-remember", "eliot-recover", "eliot-finish")])
    write_json(output / "skill-valid.json", payload)
    payload["skills"][0]["body_text"] += "\nAUDIT CORRUPTION\n"
    write_json(output / "skill-corrupt.json", payload)
    fallback_specs = None
    fallback_metadata_error = None
    report["conditional_fallback"] = dict(
        condition=None if args.runtime_edges_only else FALLBACK_CONDITION,
        status="NOT_APPLICABLE" if args.runtime_edges_only else "NOT_NEEDED")
    deadline = time.monotonic() + (42 if args.runtime_edges_only else 165) * 60
    for spec in specs:
        result = execute(spec, output, root, deadline - time.monotonic())
        report["stages"].append(result)
        if spec["name"] == "metadata" and not args.runtime_edges_only:
            try:
                if result["status"] != "EXPECTED_OUTCOME":
                    raise ValueError("metadata stage did not succeed")
                fallback_specs = fallback_plan(json.loads(Path(result["stdout"]).read_text(encoding="utf-8")))
            except (OSError, ValueError, KeyError, TypeError) as error:
                fallback_metadata_error = f"{type(error).__name__}: {error}"
            write_json(output / "plan.json", dict(ceiling=CEILING,
                       profile="native Windows dev/test; not release", stages=specs,
                       conditional_fallback=dict(condition=FALLBACK_CONDITION,
                           metadata_source="metadata.stdout.log", stages=fallback_specs,
                           resolution_error=fallback_metadata_error)))
        if spec["name"] == BROAD_TEST_STAGE:
            broad_text = "".join(Path(result[key]).read_text(encoding="utf-8", errors="replace")
                                 for key in ("stdout", "stderr") if result.get(key))
            if fallback_required(result, broad_text):
                if fallback_specs is None:
                    report["conditional_fallback"].update(status="BLOCKED", reason=fallback_metadata_error)
                else:
                    report["conditional_fallback"].update(status="TRIGGERED", packages=len(fallback_specs))
                    # Append after known blockers so their existing priority is retained.
                    specs.extend(fallback_specs)
                    write_json(output / "activated-fallback-plan.json", fallback_specs)
        if spec["name"] in ("production-build-dev", "runtime-production-build-dev"):
            inventory = binary_inventory(target, head, result["status"])
            write_json(output / "linked-binary-inventory.json", inventory)
            report["linked_binary_inventory"] = "linked-binary-inventory.json"
        write_json(output / "results.json", report)
    report["complete"] = True
    report["all_expected_outcomes"] = all(row["status"] == "EXPECTED_OUTCOME" for row in report["stages"])
    write_json(output / "results.json", report)
    summary = [CEILING, f"Source: {head}", report["profile"],
               "No installed service, live Store, model provider, release, or Product acceptance claim."]
    summary += [f"- {row['name']}: {row['status']}; exit={row['exit_code']}; {row['elapsed_seconds']}s" for row in report["stages"]]
    (output / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write("\n".join(summary) + "\n")
    return 0 if report["all_expected_outcomes"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
