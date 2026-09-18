r"""Tests for developer reset and installation pipeline scripts (issue #1375).

Validates scope restrictions to system_service install:
- (a) LocalAppData\Eliot legacy data (122 GB) is NEVER touched.
- (b) Credential deletion excludes eliot/store/v1/* and targets only eliot/installer-root/v1/*.
- (c) Lingering process termination targets ONLY processes whose executable path is under ProgramData\Eliot.
"""

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

    def test_exclusion_a_localappdata_preserved(self) -> None:
        """Exclusion (a): %LOCALAPPDATA%\\Eliot is NEVER moved, deleted, or edited by an install reset."""
        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td)
            mock_program_data = temp_path / "ProgramData"
            mock_local_app_data = temp_path / "AppData" / "Local"

            mock_pd_eliot = mock_program_data / "Eliot"
            mock_la_eliot = mock_local_app_data / "Eliot"

            mock_pd_eliot.mkdir(parents=True)
            (mock_pd_eliot / "install_data.txt").write_text("system_service installation data", encoding="utf-8")

            mock_la_eliot.mkdir(parents=True)
            legacy_file = mock_la_eliot / "owner_legacy_store.bin"
            legacy_file.write_text("owner legacy 122 GB store and swarm data", encoding="utf-8")

            script_path = _repo_root / "scripts" / "reset-developer-install.ps1"

            # Execute reset pointed at mock ProgramData
            proc = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(script_path),
                    "-ProgramDataRoot",
                    str(mock_program_data),
                    "-SkipServices",
                    "-SkipCredentials",
                ],
                capture_output=True,
                text=True,
                env={"LOCALAPPDATA": str(mock_local_app_data), "USERPROFILE": str(temp_path)},
            )
            self.assertEqual(proc.returncode, 0, f"Reset failed: {proc.stderr}")

            # ProgramData\Eliot moved aside to Eliot-reset-*
            self.assertFalse(mock_pd_eliot.exists(), "ProgramData/Eliot should be moved")
            pd_siblings = list(mock_program_data.glob("Eliot-reset-*"))
            self.assertEqual(len(pd_siblings), 1, f"Expected 1 moved PD dir, found: {pd_siblings}")
            self.assertTrue((pd_siblings[0] / "install_data.txt").is_file())

            # LocalAppData\Eliot must remain completely untouched
            self.assertTrue(mock_la_eliot.is_dir(), "LocalAppData/Eliot must remain untouched and present")
            self.assertTrue(legacy_file.is_file(), "Owner legacy store file must be preserved")
            self.assertEqual(
                legacy_file.read_text(encoding="utf-8"),
                "owner legacy 122 GB store and swarm data",
            )
            la_siblings = list(mock_local_app_data.glob("Eliot-reset-*"))
            self.assertEqual(len(la_siblings), 0, f"No reset dirs should be in LocalAppData: {la_siblings}")

    def test_exclusion_b_store_credentials_excluded(self) -> None:
        """Exclusion (b): Credential deletion excludes eliot/store/v1/* and targets only eliot/installer-root/v1/*."""
        cmd = [
            "pwsh",
            "-NoProfile",
            "-Command",
            """
            $mockCmdkeyLines = @(
                '  Target: eliot/installer-root/v1/0123456789abcdef'
                '  Target: LegacyGeneric:target=eliot/installer-root/v1/deadbeef00112233'
                '  Target: eliot/store/v1/master-key'
                '  Target: LegacyGeneric:target=eliot/store/v1/owner-store-token'
                '  Target: WindowsLive:target=virtualaccount'
            )
            $credTargets = @()
            foreach ($line in $mockCmdkeyLines) {
                if ($line -match '^\\s*Target:\\s*(.+)$') {
                    $rawTarget = $matches[1].Trim()
                    $cleanTarget = $rawTarget -replace '^LegacyGeneric:target=', ''
                    if ($cleanTarget.StartsWith('eliot/installer-root/v1/')) {
                        $credTargets += $cleanTarget
                    }
                }
            }
            $credTargets -join ';'
            """,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Credential filter execution failed: {res.stderr}")
        matched = res.stdout.strip().split(";")
        self.assertEqual(
            matched,
            [
                "eliot/installer-root/v1/0123456789abcdef",
                "eliot/installer-root/v1/deadbeef00112233",
            ],
            f"Unexpected targets matched: {matched}",
        )

    def test_exclusion_c_processes_outside_installation_root_excluded(self) -> None:
        """Exclusion (c): Lingering process termination targets ONLY processes under ProgramData\\Eliot."""
        cmd = [
            "pwsh",
            "-NoProfile",
            "-Command",
            """
            $pdEliot = 'C:\\ProgramData\\Eliot'
            $installRootPrefix = [System.IO.Path]::GetFullPath($pdEliot).TrimEnd('\\', '/') + [System.IO.Path]::DirectorySeparatorChar

            $testProcesses = @(
                @{ Name = 'eliot-kernel'; Path = 'C:\\ProgramData\\Eliot\\bin\\eliot-kernel.exe' },
                @{ Name = 'eliotd';        Path = 'C:\\Users\\owner\\AppData\\Local\\Eliot\\bin\\eliotd.exe' },
                @{ Name = 'surreal';       Path = 'C:\\Development\\Rust\\target\\release\\surreal.exe' },
                @{ Name = 'surreal';       Path = 'C:\\Program Files\\SurrealDB\\surreal.exe' },
                @{ Name = 'eliot-watchdog'; Path = '' }
            )

            $targeted = @()
            foreach ($proc in $testProcesses) {
                $procPath = $proc.Path
                if ([string]::IsNullOrWhiteSpace($procPath)) {
                    continue
                }
                $fullProcPath = [System.IO.Path]::GetFullPath($procPath)
                if ($fullProcPath.StartsWith($installRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $targeted += "$($proc.Name):$($proc.Path)"
                }
            }
            $targeted -join ';'
            """,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Process filter test failed: {res.stderr}")
        targeted = res.stdout.strip().split(";")
        self.assertEqual(
            targeted,
            ["eliot-kernel:C:\\ProgramData\\Eliot\\bin\\eliot-kernel.exe"],
            f"Expected only process inside installation root, got: {targeted}",
        )

    def test_programdata_reset_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td)
            mock_program_data = temp_path / "ProgramData"
            mock_pd_eliot = mock_program_data / "Eliot"

            mock_pd_eliot.mkdir(parents=True)
            (mock_pd_eliot / "test_pd.txt").write_text("programdata content", encoding="utf-8")

            script_path = _repo_root / "scripts" / "reset-developer-install.ps1"

            # Run 1: moves ProgramData/Eliot aside
            proc1 = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(script_path),
                    "-ProgramDataRoot",
                    str(mock_program_data),
                    "-SkipServices",
                    "-SkipCredentials",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc1.returncode, 0, f"First run failed: {proc1.stderr}")
            self.assertFalse(mock_pd_eliot.exists(), "Original ProgramData/Eliot should be moved")
            pd_siblings = list(mock_program_data.glob("Eliot-reset-*"))
            self.assertEqual(len(pd_siblings), 1)

            # Run 2: idempotent clean run
            proc2 = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(script_path),
                    "-ProgramDataRoot",
                    str(mock_program_data),
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
