"""Unit tests for GitHub workflow verifier (issue #1225)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

# Load scripts/verify-github-workflows.py dynamically
_script_path = Path(__file__).resolve().parents[1] / "verify-github-workflows.py"
_spec = importlib.util.spec_from_file_location("verify_github_workflows", _script_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {_script_path}")
vgw = importlib.util.module_from_spec(_spec)
sys.modules["verify_github_workflows"] = vgw
_spec.loader.exec_module(vgw)

parse_workflow_events = vgw.parse_workflow_events
check_workflows = vgw.check_workflows
check_python_requirements = vgw.check_python_requirements
check_nuget_lock = vgw.check_nuget_lock
verify_all = vgw.verify_all


class TestVerifyGithubWorkflows(unittest.TestCase):
    def test_parse_workflow_events(self) -> None:
        self.assertEqual(parse_workflow_events("on: workflow_dispatch\n"), {"workflow_dispatch"})
        self.assertEqual(parse_workflow_events("on:\n  workflow_dispatch:\n"), {"workflow_dispatch"})
        self.assertEqual(parse_workflow_events("on: [push, pull_request]\n"), {"push", "pull_request"})
        self.assertEqual(parse_workflow_events("on:\n  push:\n  pull_request:\n"), {"push", "pull_request"})

    def test_workflow_trigger_push_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text("on: push\n", encoding="utf-8")
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-001" for f in findings))

    def test_workflow_mutable_action_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(
                "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-002" for f in findings))

    def test_workflow_write_all_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(
                "name: Manual Gate\non:\n  workflow_dispatch:\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
                encoding="utf-8",
            )
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-003" for f in findings))

    def test_workflow_build_only_operator_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(
                "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj\n",
                encoding="utf-8",
            )
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-006" for f in findings))

    def test_python_requirements_unhashed_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            scripts_dir = root / "scripts"
            scripts_dir.mkdir(parents=True)
            (scripts_dir / "requirements-verification.txt").write_text("jsonschema==4.25.1\n", encoding="utf-8")
            findings = check_python_requirements(root)
            self.assertTrue(any(f.code == "GWF-004" for f in findings))

    def test_python_requirements_hashed_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            scripts_dir = root / "scripts"
            scripts_dir.mkdir(parents=True)
            (scripts_dir / "requirements-verification.txt").write_text(
                "jsonschema==4.25.1 \\\n    --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
                encoding="utf-8",
            )
            findings = check_python_requirements(root)
            self.assertEqual(findings, [])

    def test_nuget_lock_missing_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            op_dir = root / "apps" / "Eliot.Operator"
            op_dir.mkdir(parents=True)
            (op_dir / "Eliot.Operator.csproj").write_text("<Project><PropertyGroup></PropertyGroup></Project>", encoding="utf-8")
            findings = check_nuget_lock(root)
            self.assertTrue(any(f.code == "GWF-005" for f in findings))

    def test_current_repository_passes(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        findings = verify_all(repo_root)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
