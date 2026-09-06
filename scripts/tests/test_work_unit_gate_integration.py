"""#837 containment regressions for the legacy false-green entrypoint.

These test the real CLI, not the future complete gate. Only cases 14 and 23 of
#837 are addressed here. This file cannot certify the remaining 40 obligations.
No Rust toolchain, candidate imports or external service is required.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / 'scripts/verify-work-unit.py'


def load_cli():
    spec = importlib.util.spec_from_file_location('legacy_work_unit_cli', ENTRYPOINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(root: Path, *, assertion: str = 'false') -> None:
    (root / 'Cargo.toml').write_text('[workspace]\nmembers = ["subject"]\n')
    package = root / 'subject'
    (package / 'src').mkdir(parents=True)
    (package / 'Cargo.toml').write_text('[package]\nname = "subject"\nversion = "0.0.0"\nedition = "2021"\n')
    (package / 'module.toml').write_text('''module_id = "regression.subject"
[acceptance]
min_source_lines = 1
required_exports = ["answer"]
required_tests = ["always_fails"]
min_tests = 1
''')
    (package / 'src/lib.rs').write_text('''#![forbid(unsafe_code)]
pub fn answer() -> bool { false }
#[test]
fn always_fails() { assert!(''' + assertion + '''); }
''')


class LegacyCompletionSafetyTests(unittest.TestCase):
    def run_main(self, root, *flags):
        cli = load_cli()
        output = io.StringIO()
        with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), *flags]), redirect_stdout(output), redirect_stderr(output):
            result = cli.main()
        return result, output.getvalue()

    # WORK_UNIT_CASE: 837/14
    def test_discovery_exit_and_list_cannot_certify_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            # The old implementation accepted this successful test listing,
            # even though the actual declared Rust test unconditionally fails.
            listed = subprocess.CompletedProcess(['cargo'], 0, 'always_fails: test\n', '')
            with patch.object(subprocess, 'run', return_value=listed) as process:
                code, output = self.run_main(root)
            self.assertNotEqual(0, code)
            self.assertIn('execution=NOT_RUN', output)
            self.assertIn('completion=NOT_VERIFIED', output)
            process.assert_not_called()

    # WORK_UNIT_CASE: 837/23
    def test_no_cargo_cannot_claim_complete_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            with patch.object(subprocess, 'run', side_effect=AssertionError('unexpected execution')):
                code, output = self.run_main(root, '--no-cargo')
            self.assertEqual(1, code)
            self.assertIn('INCOMPLETE:', output)
            self.assertIn('case-binding=NOT_CHECKED', output)
            self.assertNotIn('passed, 0 failed', output)
            self.assertNotIn('  PASS ', output)

    def test_reproduces_false_green_through_actual_cli_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            proc = subprocess.run([sys.executable, str(ENTRYPOINT), '--crate', 'subject', '--root', str(root), '--no-cargo'],
                                  capture_output=True, text=True, timeout=5)
            self.assertEqual(1, proc.returncode, proc.stderr)
            self.assertIn('No work unit is accepted.', proc.stdout)
            self.assertIn('completion=NOT_VERIFIED', proc.stdout)

    def test_green_looking_source_is_still_only_a_shape_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, assertion='true')
            for flags in ((), ('--no-cargo',)):
                with self.subTest(flags=flags):
                    code, output = self.run_main(root, *flags)
                    self.assertEqual(1, code)
                    self.assertIn('0 findings', output)
                    self.assertIn('proof=legacy-source-shape-only', output)

    def test_existing_shape_failures_remain_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / 'subject/src/lib.rs').write_text('')
            code, output = self.run_main(root, '--no-cargo')
            self.assertEqual(1, code)
            self.assertIn('FAIL  export `answer`', output)
            self.assertIn('FAIL  test `always_fails`', output)
            self.assertIn('completion=NOT_VERIFIED', output)

    def test_missing_configuration_remains_a_configuration_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / 'subject/module.toml').unlink()
            code, output = self.run_main(root, '--no-cargo')
            self.assertEqual(2, code)
            self.assertIn('missing', output)

    def test_diagnostics_leave_inputs_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.run_main(root)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)

    def test_help_does_not_claim_acceptance(self):
        proc = subprocess.run([sys.executable, str(ENTRYPOINT), '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(0, proc.returncode)
        self.assertIn('NOT work-unit completion evidence', proc.stdout)
        self.assertNotIn('proves the crate is', proc.stdout)

    def test_unknown_override_is_rejected_before_inspection(self):
        cli = load_cli()
        with patch.object(sys, 'argv', [str(ENTRYPOINT), '--crate', 'subject', '--accept-anyway']), \
             patch.object(cli, 'crate_dir', side_effect=AssertionError('unexpected inspection')), \
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            cli.main()
        self.assertEqual(2, error.exception.code)


if __name__ == '__main__':
    unittest.main()
