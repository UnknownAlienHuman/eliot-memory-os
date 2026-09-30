#!/usr/bin/env python3
"""Existing locked Operator commands, isolated diagnostic accounting, no live UI."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

CEILING = "OPERATOR_LOCKED_BUILD_AND_HEADLESS_HARNESS_ONLY_NOT_INSTALLED_ACCEPTANCE"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if os.name != "nt" or os.environ.get("GITHUB_REF") != "refs/heads/Operator_tests":
        raise RuntimeError("Operator diagnostics require the admitted Windows audit branch")
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if sha != os.environ.get("GITHUB_SHA"):
        raise RuntimeError("source identity mismatch")
    output = Path(args.output).resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if output == runner_temp or not output.is_relative_to(runner_temp):
        raise RuntimeError("output must be a dedicated child of runner temp")
    output.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("operator_diagnostic_runner", root / "scripts/operator-audit-diagnostic.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("existing diagnostic executor unavailable")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    app = "apps/Eliot.Operator/Eliot.Operator.csproj"
    tests = "tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj"
    # Exact commands from verify.ps1 restore/build owners and the normal
    # source-candidate harness step. No --live, deployment or policy bypass.
    stages = [
        runner.stage("dotnet-sdk-identity", ["dotnet", "--info"], 2),
        runner.stage("operator-locked-restore", ["dotnet", "restore", app, "--locked-mode"], 5),
        runner.stage("operator-tests-locked-restore", ["dotnet", "restore", tests, "--locked-mode"], 5),
        runner.stage("operator-build", ["dotnet", "build", app, "-c", "Release", "--no-restore"], 5),
        runner.stage("operator-tests-build", ["dotnet", "build", tests, "-c", "Release", "--no-restore"], 5),
        runner.stage("operator-headless-harness", ["dotnet", "run", "--project", tests, "-c", "Release", "--no-restore"], 3,
                     contains="tests passed; assertions="),
    ]
    report = {"source": sha, "proof_ceiling": CEILING,
              "os_identity": {"system": platform.system(), "release": platform.release(),
                              "version": platform.version(), "machine": platform.machine()},
              "stages": []}
    (output / "plan.json").write_text(json.dumps({"source": sha, "proof_ceiling": CEILING, "stages": stages}, indent=2))
    start = time.monotonic()
    for stage in stages:
        result = runner.execute(stage, output, root, 24 * 60 - (time.monotonic() - start))
        if stage["name"] == "operator-headless-harness":
            path = output / "operator-headless-harness.stdout.log"
            text = path.read_text(errors="replace") if path.exists() else ""
            counts = re.findall(r"tests passed; assertions=(\d+)", text)
            result["executed_assertions"] = int(counts[-1]) if len(counts) == 1 else None
            if result["status"] == "EXPECTED_OUTCOME" and not result["executed_assertions"]:
                result.update(status="FAILED", reason="missing positive executed-assertion receipt")
        report["stages"].append(result)
        (output / "result.json").write_text(json.dumps(report, indent=2))
    return int(any(row["status"] != "EXPECTED_OUTCOME" for row in report["stages"]))


if __name__ == "__main__":
    raise SystemExit(main())
