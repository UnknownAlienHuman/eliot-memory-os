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
check_action_pin_divergence = vgw.check_action_pin_divergence
collect_action_identities = vgw.collect_action_identities
check_python_requirements = vgw.check_python_requirements
check_nuget_lock = vgw.check_nuget_lock
check_pip_install_lock = vgw.check_pip_install_lock
verify_all = vgw.verify_all

CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
CACHE_SHA = "1bd1e32a3bdc45362d1e726936510720a7c30a57"
OTHER_SHA = "a" * 40
# An otherwise conforming manual-dispatch workflow, so a rejection in an
# action-identity test can only come from the action rule under test.
GATE = (
    "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
    "    runs-on: ubuntu-latest\n    steps:\n      {body}\n"
)


def _write_workflow(root: Path, filename: str, text: str) -> None:
    wf_dir = root / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / filename).write_text(text, encoding="utf-8")


def _step_uses(ref: str) -> str:
    return GATE.format(body=f"- uses: {ref}")


def _job_uses(ref: str) -> str:
    # Job-level reusable workflow `uses:` carries no leading dash.
    return (
        "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\n"
        "jobs:\n  t:\n    uses: " + ref + "\n"
    )


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

    def test_nuget_harness_lock_missing_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            harness_dir = root / "tests" / "Eliot.Operator.Tests"
            harness_dir.mkdir(parents=True)
            (harness_dir / "Eliot.Operator.Tests.csproj").write_text(
                "<Project><PropertyGroup></PropertyGroup></Project>", encoding="utf-8"
            )
            findings = check_nuget_lock(root)
            self.assertTrue(
                any(f.code == "GWF-005" and "Eliot.Operator.Tests" in f.path for f in findings)
            )

    def test_nuget_harness_locked_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            harness_dir = root / "tests" / "Eliot.Operator.Tests"
            harness_dir.mkdir(parents=True)
            (harness_dir / "Eliot.Operator.Tests.csproj").write_text(
                "<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>"
                "</PropertyGroup></Project>",
                encoding="utf-8",
            )
            (harness_dir / "packages.lock.json").write_text(
                '{"version": 1, "dependencies": {"net10.0": {}}}', encoding="utf-8"
            )
            findings = check_nuget_lock(root)
            self.assertEqual(findings, [])

    def test_pip_install_unhashed_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(
                "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
                "    runs-on: windows-latest\n    steps:\n"
                "      - run: python -m pip install -r scripts/requirements.txt\n",
                encoding="utf-8",
            )
            findings = check_pip_install_lock(root)
            self.assertTrue(any(f.code == "GWF-009" for f in findings))

    def test_pip_install_hash_locked_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "test.yml").write_text(
                "name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  t:\n"
                "    runs-on: windows-latest\n    steps:\n"
                "      - run: python -m pip install --require-hashes -r scripts/requirements-verification.txt\n",
                encoding="utf-8",
            )
            findings = check_pip_install_lock(root)
            self.assertEqual(findings, [])

    def test_workflow_unapproved_action_owner_rejected(self) -> None:
        # A syntactically valid full 40-hex SHA is not on its own an approved
        # identity: the owner must be in the closed approved set.
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "test.yml", _step_uses(f"evilcorp/checkout@{CHECKOUT_SHA}"))
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-002" and "evilcorp" in f.detail for f in findings))

    def test_workflow_approved_action_owner_full_sha_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "test.yml", _step_uses(f"actions/checkout@{CHECKOUT_SHA} # v4.2.2"))
            self.assertEqual(check_workflows(root), [])

    def test_workflow_reusable_workflow_uses_is_covered(self) -> None:
        # Job-level `uses:` has no leading dash. The dash-optional ACTION_REF_RE
        # is the only thing that parses it; a mutable ref here must fail.
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "test.yml", _job_uses("actions/reusable/.github/workflows/x.yml@v1"))
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-002" and "v1" in f.detail for f in findings))

    def test_workflow_reusable_workflow_pinned_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "test.yml", _job_uses(f"actions/reusable/.github/workflows/x.yml@{CHECKOUT_SHA}"))
            self.assertEqual(check_workflows(root), [])

    def test_workflow_expression_ref_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "test.yml", _step_uses("actions/checkout@${{ env.ACTION_SHA }}"))
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-002" for f in findings))

    def test_workflow_reusable_expression_ref_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "test.yml", _job_uses("actions/reusable/.github/workflows/x.yml@${{ inputs.ref }}"))
            self.assertTrue(any(f.code == "GWF-002" for f in check_workflows(root)))

    def test_workflow_malformed_action_name_rejected(self) -> None:
        # No owner segment: not an owner/repository identity at all.
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "test.yml", _step_uses(f"checkout@{CHECKOUT_SHA}"))
            findings = check_workflows(root)
            self.assertTrue(any(f.code == "GWF-010" for f in findings))

    def test_workflow_short_and_branch_refs_rejected(self) -> None:
        for ref in ("actions/checkout@11bd7190", "actions/checkout@main", "actions/checkout@*"):
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                _write_workflow(root, "test.yml", _step_uses(ref))
                self.assertTrue(
                    any(f.code == "GWF-002" for f in check_workflows(root)), f"ref {ref} was accepted"
                )

    def test_divergent_action_pin_rejected(self) -> None:
        # Same action, two different SHAs across two workflows: each reference
        # is individually well-formed, so only the repository-level check fails.
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "a.yml", _step_uses(f"actions/checkout@{CHECKOUT_SHA}"))
            _write_workflow(root, "b.yml", _step_uses(f"actions/checkout@{OTHER_SHA}"))
            findings = check_action_pin_divergence(root)
            self.assertTrue(any(f.code == "GWF-011" for f in findings))

    def test_divergence_included_in_verify_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "a.yml", _step_uses(f"actions/checkout@{CHECKOUT_SHA}"))
            _write_workflow(root, "b.yml", _step_uses(f"actions/checkout@{OTHER_SHA}"))
            self.assertTrue(any(f.code == "GWF-011" for f in verify_all(root)))

    def test_consistent_action_pin_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "a.yml", _step_uses(f"actions/checkout@{CHECKOUT_SHA}"))
            _write_workflow(root, "b.yml", _step_uses(f"actions/checkout@{CHECKOUT_SHA} # v4.2.2"))
            self.assertEqual(check_action_pin_divergence(root), [])

    def test_collected_action_identities_are_derived_and_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_workflow(root, "b.yml", _step_uses(f"actions/cache@{CACHE_SHA} # v4.2.0"))
            _write_workflow(
                root,
                "a.yml",
                _step_uses(f"actions/checkout@{CHECKOUT_SHA} # v4.2.2")
                + _job_uses(f"actions/reusable/.github/workflows/x.yml@{OTHER_SHA}"),
            )
            identities = collect_action_identities(root)
            self.assertEqual(
                [(i["workflow"], i["action"], i["ref"]) for i in identities],
                [
                    (".github/workflows/a.yml", "actions/checkout", CHECKOUT_SHA),
                    (".github/workflows/a.yml", "actions/reusable/.github/workflows/x.yml", OTHER_SHA),
                    (".github/workflows/b.yml", "actions/cache", CACHE_SHA),
                ],
            )
            # Deterministic: a second derivation of the same tree is identical.
            self.assertEqual(collect_action_identities(root), identities)

    def test_repository_action_identities_are_fully_covered(self) -> None:
        # Every live third-party `uses:` in this repository must be recorded,
        # including the job-scope (no dash) `uses:` form, and all on one SHA per
        # action. This is the complete-coverage property, not a fixture example.
        repo_root = Path(__file__).resolve().parents[2]
        identities = collect_action_identities(repo_root)
        refs_by_action: dict[str, set[str]] = {}
        for record in identities:
            refs_by_action.setdefault(record["action"], set()).add(record["ref"])
        self.assertEqual(len(identities), 12)
        self.assertEqual(set(refs_by_action), {"actions/checkout", "actions/cache"})
        for action, refs in refs_by_action.items():
            self.assertEqual(len(refs), 1, f"{action} has divergent refs {refs}")
        for record in identities:
            self.assertRegex(record["ref"], r"^[0-9a-fA-F]{40}$")

    def test_current_repository_passes(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        findings = verify_all(repo_root)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
