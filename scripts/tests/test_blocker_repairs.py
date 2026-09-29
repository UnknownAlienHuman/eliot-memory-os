"""Focused #3004/#1229 regression checks; no Cargo build, Rust tests or network.

The PowerShell discriminator replaces the gate command table and the three
identity probes in a temporary copy. It executes the production orchestration
and summary, not real gates or toolchains. Its PASS is failure-isolation proof
only, never MergeCompile or Product PASS.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / name)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Cannot load {name}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BlockerRepairs(unittest.TestCase):
    def test_standalone_resolution_flags_match_before_compile(self):
        module = load_script('verify-standalone-crates.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for present, flag in ((False, '--offline'), (True, '--locked')):
                if present:
                    (root / 'Cargo.lock').write_text('version = 4\n', encoding='utf-8')
                steps = dict(module.compile_steps(root))
                self.assertIn(flag, steps['clippy'])
                self.assertIn(flag, steps['test-no-run'])
                self.assertIn('--no-run', steps['test-no-run'])
                self.assertNotIn('-D', steps['clippy'])

    def test_historical_snapshot_requires_actual_pinned_bytes(self):
        module = load_script('provision-surrealdb-release.py')
        # Any accidental historical network call is a test failure.
        def forbidden_fetch(*args, **kwargs):
            self.fail('historical snapshot acquisition attempted a live request')
        module.fetch = forbidden_fetch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = '.eliot/dependency-policy/surrealdb/frozen/response.json'
            policy = {'advisory_response_path': relative,
                      'advisory_response_digest': module.sha256_bytes(b'{"vulns":[]}')}
            with self.assertRaisesRegex(RuntimeError, 'HISTORICAL_OSV_INPUT_REQUIRED'):
                module.read_historical_advisory(root, policy)
            source = root / relative
            source.parent.mkdir(parents=True)
            source.write_text('{"vulns": []}\n', encoding='utf-8')
            self.assertEqual(module.read_historical_advisory(root, policy), b'{"vulns":[]}')
            supplied = '.eliot/dependency-policy/surrealdb/import/response.json'
            imported = root / supplied
            imported.parent.mkdir()
            imported.write_text('{"vulns": []}', encoding='utf-8')
            self.assertEqual(module.read_historical_advisory(root, policy, supplied), b'{"vulns":[]}')
            imported.write_text('{"vulns": [{"id": "changed"}]}', encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'HISTORICAL_OSV_DIGEST_MISMATCH'):
                module.read_historical_advisory(root, policy, supplied)
            with self.assertRaises(ValueError):
                module.read_historical_advisory(root, policy, '../outside.json')
            source.write_text('{bad', encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'not valid JSON'):
                module.read_historical_advisory(root, policy)

    def run_profile_discriminator(self, profile: str, failure: str = ''):
        pwsh = shutil.which('pwsh')
        if pwsh is None:
            self.skipTest('PowerShell runtime unavailable; failure-isolation proof NOT EXECUTED')
        source = (ROOT / 'scripts/verify.ps1').read_text(encoding='utf-8')
        start = source.index('$allGates = @(\n')
        end = source.index('\n$profileExplicit = ', start)
        gates = []
        for name in ('dependency-policy-offline', 'cargo-metadata', 'cargo-check-workspace',
                     'cargo-denominator', 'cargo-clippy-changed',
                     'dotnet-restore-operator', 'dotnet-build-operator'):
            command = f"Write-Host 'DISCRIMINATOR_RAN:{name}'"
            if name == failure:
                command = "throw 'injected failure'"
            elif name == 'cargo-metadata':
                command += "; $script:verifyMetadataJson = '{\"packages\":[]}'"
            gates.append("    [pscustomobject]@{ Name = '" + name
                         + "'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { "
                         + command + " } }")
        # Identity probes are not the property under test. Calling the runner's
        # rustup shim here can install Cargo before the first discriminator and
        # turn a gate-order test into a network/toolchain-dependent timeout.
        # Intercept only the exact observation commands; unexpected calls fail.
        probes = r"""
function cargo {
    if ($args.Count -ne 1 -or $args[0] -cne '--version') {
        throw 'DISCRIMINATOR_UNEXPECTED_CARGO_CALL'
    }
    Write-Output 'cargo synthetic-orchestration-identity'
}
function python {
    if ($args.Count -ne 1 -or $args[0] -cne '--version') {
        throw 'DISCRIMINATOR_UNEXPECTED_PYTHON_CALL'
    }
    Write-Output 'Python synthetic-orchestration-identity'
}
function git {
    if ($args.Count -ne 2 -or $args[0] -cne 'rev-parse' -or $args[1] -cne 'HEAD') {
        throw 'DISCRIMINATOR_UNEXPECTED_GIT_CALL'
    }
    Write-Output 'synthetic-orchestration-source'
}
"""
        table = probes + '$allGates = @(\n' + ',\n'.join(gates) + '\n)\n'
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory) / 'scripts'
            scripts.mkdir()
            (Path(directory) / '.eliot').mkdir()
            candidate = scripts / 'verify.ps1'
            candidate.write_text(source[:start] + table + source[end:], encoding='utf-8')
            result = subprocess.run([pwsh, '-NoProfile', '-File', str(candidate),
                                     '-Profile', profile], capture_output=True, text=True, timeout=60)
            self.assertNotIn('VERIFY_HARNESS:', result.stdout, result.stdout + result.stderr)
            self.assertIn('cargo synthetic-orchestration-identity', result.stdout)
            self.assertIn('Python synthetic-orchestration-identity', result.stdout)
            self.assertIn('source=synthetic-orchestration-source', result.stdout)
            return result

    def test_mergecompile_failure_does_not_hide_independent_compile(self):
        result = self.run_profile_discriminator('MergeCompile', 'dependency-policy-offline')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('VERIFY_GATE: cargo-check-workspace pass', result.stdout)
        self.assertIn('VERIFY_GATE: dotnet-build-operator pass', result.stdout)
        self.assertIn('VERIFY_RESULT: FAIL', result.stdout)
        self.assertIn('passed=6 failed=1 not-run=0', result.stdout)

    def test_mergecompile_missing_producer_blocks_only_its_consumers(self):
        result = self.run_profile_discriminator('MergeCompile', 'cargo-metadata')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for name in ('cargo-check-workspace', 'cargo-denominator', 'cargo-clippy-changed'):
            self.assertIn(f'VERIFY_GATE: {name} not-run', result.stdout)
            self.assertNotIn(f'DISCRIMINATOR_RAN:{name}', result.stdout)
        self.assertIn('VERIFY_GATE: dotnet-build-operator pass', result.stdout)
        self.assertIn('passed=3 failed=1 not-run=3', result.stdout)

    def test_restore_failure_does_not_use_stale_dotnet_assets(self):
        result = self.run_profile_discriminator('MergeCompile', 'dotnet-restore-operator')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('VERIFY_GATE: dotnet-build-operator not-run', result.stdout)
        self.assertNotIn('DISCRIMINATOR_RAN:dotnet-build-operator', result.stdout)

    def test_all_passing_selected_gates_allow_pass(self):
        result = self.run_profile_discriminator('MergeCompile')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('passed=7 failed=0 not-run=0', result.stdout)

    def test_quick_and_review_remain_fail_fast(self):
        for profile in ('Quick', 'Review'):
            with self.subTest(profile=profile):
                result = self.run_profile_discriminator(profile, 'dependency-policy-offline')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertNotIn('DISCRIMINATOR_RAN:cargo-metadata', result.stdout)
                self.assertIn('passed=0 failed=1 not-run=6', result.stdout)


if __name__ == '__main__':
    unittest.main()
