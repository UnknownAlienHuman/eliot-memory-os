"""Tests for developer reset and installation pipeline scripts (issue #1375)."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

_repo_root = Path(__file__).resolve().parents[2]


class TestResetDeveloperInstall(unittest.TestCase):
    def test_scripts_parse(self) -> None:
        scripts = [
            _repo_root / "scripts" / "reset-developer-install.ps1",
            _repo_root / "scripts" / "install-pipeline.ps1",
        ]
        for script in scripts:
            self.assertTrue(script.is_file(), f"Script not found: {script}")
            escaped_path = str(script).replace("'", "''")
            cmd = [
                "pwsh",
                "-NoProfile",
                "-Command",
                f"$tokens = $null; $errors = $null; "
                f"[System.Management.Automation.Language.Parser]::ParseFile('{escaped_path}', [ref]$tokens, [ref]$errors); "
                f"if ($errors.Count -gt 0) {{ foreach ($e in $errors) {{ Write-Error $e.ToString() }}; exit $errors.Count }} exit 0",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Script parse failed for {script}: {res.stderr}")

    def test_reset_dry_run(self) -> None:
        script = _repo_root / "scripts" / "reset-developer-install.ps1"
        res = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(script), "-WhatIf"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Reset dry run failed: {res.stderr}")

    def test_install_pipeline_reset_dry_run(self) -> None:
        script = _repo_root / "scripts" / "install-pipeline.ps1"
        res = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(script), "-Reset", "-WhatIf"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Install pipeline reset dry run failed: {res.stderr}")

    def test_mock_directory_reset_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td)
            mock_program_data = temp_path / "ProgramData"
            mock_local_app_data = temp_path / "AppData" / "Local"

            mock_pd_eliot = mock_program_data / "Eliot"
            mock_la_eliot = mock_local_app_data / "Eliot"

            mock_pd_eliot.mkdir(parents=True)
            (mock_pd_eliot / "test_pd.txt").write_text("programdata content", encoding="utf-8")

            mock_la_eliot.mkdir(parents=True)
            (mock_la_eliot / "test_la.txt").write_text("localappdata content", encoding="utf-8")

            script_path = _repo_root / "scripts" / "reset-developer-install.ps1"

            # First run: moves directories aside
            proc1 = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(script_path),
                    "-ProgramDataRoot",
                    str(mock_program_data),
                    "-LocalAppDataRoot",
                    str(mock_local_app_data),
                    "-SkipServices",
                    "-SkipCredentials",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc1.returncode, 0, f"First run failed: {proc1.stderr}")
            self.assertFalse(mock_pd_eliot.exists(), "Original ProgramData/Eliot should be moved")
            self.assertFalse(mock_la_eliot.exists(), "Original LocalAppData/Eliot should be moved")

            # Check moved siblings exist
            pd_siblings = list(mock_program_data.glob("Eliot-reset-*"))
            la_siblings = list(mock_local_app_data.glob("Eliot-reset-*"))
            self.assertEqual(len(pd_siblings), 1, f"Expected 1 moved PD dir, found: {pd_siblings}")
            self.assertEqual(len(la_siblings), 1, f"Expected 1 moved LA dir, found: {la_siblings}")
            self.assertTrue((pd_siblings[0] / "test_pd.txt").is_file())
            self.assertTrue((la_siblings[0] / "test_la.txt").is_file())

            # Second run: machine is clean, assert idempotency
            proc2 = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(script_path),
                    "-ProgramDataRoot",
                    str(mock_program_data),
                    "-LocalAppDataRoot",
                    str(mock_local_app_data),
                    "-SkipServices",
                    "-SkipCredentials",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc2.returncode, 0, f"Second run failed: {proc2.stderr}")
            self.assertIn("nothing to reset", proc2.stdout)

    def test_readme_indexing(self) -> None:
        readme = _repo_root / "scripts" / "README.md"
        self.assertTrue(readme.is_file(), "scripts/README.md not found")
        content = readme.read_text(encoding="utf-8")
        self.assertIn("reset-developer-install.ps1", content)
        self.assertIn("install-pipeline.ps1", content)


if __name__ == "__main__":
    unittest.main()
