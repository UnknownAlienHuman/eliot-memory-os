"""Declaration/diagnostic regressions for #870; fakes never prove live Rust.

The separately required clean bootstrap remains real environment evidence,
not a skipped unit test or a mocked result promoted to a completed issue.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-wasm-toolchain.py"
spec = importlib.util.spec_from_file_location("eliot_wasm_toolchain_check", SCRIPT)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = check
spec.loader.exec_module(check)
VALID = (ROOT / "scripts/testdata/wasm-toolchain/valid.toml").read_bytes()


class ToolchainTests(unittest.TestCase):
    def assert_rejected(self, raw: bytes, code: str) -> None:
        with self.assertRaises(check.ToolchainError) as failure:
            check.parse_declaration(raw)
        self.assertEqual(str(failure.exception), code)

    def fake_tools(self, *, missing_guest=False, artifact=True, bad_header=False, fail_compile=False):
        calls = []

        def run(argv, cwd, timeout):
            calls.append(tuple(argv))
            if argv[1:] == ["toolchain", "list"]:
                return check.CommandResult("OK", b"1.97.1-x86_64-unknown-linux-gnu (default)\n")
            if "--version" in argv:
                return check.CommandResult("OK", b"rustc 1.97.1\nrelease: 1.97.1\ncommit-hash: " + b"a" * 40 + b"\n")
            if argv[1:3] == ["target", "list"]:
                data = (check.HOST_TARGET + "\n").encode()
                if not missing_guest:
                    data += (check.GUEST_TARGET + "\n").encode()
                return check.CommandResult("OK", data)
            if "--crate-type=bin" in argv:
                self.assertEqual((cwd / "probe.rs").read_bytes(), check.PROBE_SOURCE)
                self.assertEqual(argv[argv.index("--target") + 1], check.GUEST_TARGET)
                self.assertNotIn("target", [p.name for p in cwd.iterdir()])
                if fail_compile:
                    return check.CommandResult("TOOL_FAILED", b"secret compiler diagnostics")
                if artifact:
                    header = b"\x00asm\x01\x00\x00\x00" if bad_header else check.COMPONENT_HEADER
                    (cwd / "probe.wasm").write_bytes(header + b"fixture")
                return check.CommandResult("OK")
            self.fail(f"unexpected command in fixture: {argv}")

        return calls, run

    def observe(self, *, probe=False, **fixture):
        calls, run = self.fake_tools(**fixture)
        with patch.object(check.shutil, "which", return_value="/admitted/rustup"), patch.object(check, "_run", side_effect=run):
            result = check.diagnose(check.parse_declaration(VALID), probe=probe)
        return result, calls

    # WORK_UNIT_CASE: 870/1
    def test_current_declaration_matches_frozen_policy(self):
        self.assertEqual(check.read_declaration(ROOT), check.parse_declaration(VALID))

    # WORK_UNIT_CASE: 870/2
    def test_channel_is_pinned_not_moving_or_noncanonical(self):
        for channel in (b"stable", b"nightly", b"beta", b"1.97", b"1.097.1", b"1.97.01", b"custom/1.97.1"):
            with self.subTest(channel=channel):
                self.assert_rejected(VALID.replace(b"1.97.1", channel), "CHANNEL_NOT_PINNED")
        self.assert_rejected(VALID.replace(b"1.97.1", b"1.81.0"), "CHANNEL_PREDATES_WASIP2_TIER2")

    # WORK_UNIT_CASE: 870/3
    def test_host_target_is_mandatory(self):
        self.assert_rejected(VALID.replace(b'"x86_64-pc-windows-msvc", ', b""), "HOST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/4
    def test_exact_component_guest_is_declared_once(self):
        self.assertEqual(check.parse_declaration(VALID).targets.count(check.GUEST_TARGET), 1)
        self.assert_rejected(VALID.replace(b'"wasm32-wasip2"', b'"wasm32-wasip1"'), "GUEST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/5
    def test_missing_guest_has_prerequisite_error(self):
        self.assert_rejected(VALID.replace(b', "wasm32-wasip2"', b""), "GUEST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/6
    def test_duplicate_guest_is_rejected(self):
        self.assert_rejected(VALID.replace(b'"wasm32-wasip2"', b'"wasm32-wasip2", "wasm32-wasip2"'), "DUPLICATE_TARGETS")

    # WORK_UNIT_CASE: 870/7
    def test_unknown_guest_cannot_replace_supported_guest(self):
        self.assert_rejected(VALID.replace(b'"wasm32-wasip2"', b'"unknown-target"'), "GUEST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/8
    def test_extra_wasm_or_host_target_is_unowned(self):
        for extra in (b"wasm32-wasip3", b"wasm32-unknown-unknown", b"aarch64-pc-windows-msvc"):
            with self.subTest(extra=extra):
                self.assert_rejected(VALID.replace(b'"wasm32-wasip2"', b'"wasm32-wasip2", "' + extra + b'"'), "UNOWNED_TARGET")

    # WORK_UNIT_CASE: 870/9
    def test_equivalent_set_order_preserves_identity(self):
        reordered = VALID.replace(b'"x86_64-pc-windows-msvc", "wasm32-wasip2"', b'"wasm32-wasip2", "x86_64-pc-windows-msvc"')
        reordered = reordered.replace(b'"clippy", "rustfmt"', b'"rustfmt", "clippy"')
        self.assertEqual(check.parse_declaration(VALID).digest, check.parse_declaration(reordered).digest)

    # WORK_UNIT_CASE: 870/10
    def test_changed_pinned_channel_changes_identity(self):
        self.assertNotEqual(check.parse_declaration(VALID).digest, check.parse_declaration(VALID.replace(b"1.97.1", b"1.97.2")).digest)

    # WORK_UNIT_CASE: 870/11
    def test_guest_is_load_bearing_in_identity(self):
        declared = check.parse_declaration(VALID)
        # Direct value comparison tests digest sensitivity; public file parsing
        # separately refuses this unadmitted target, rather than accepting it.
        changed = replace(declared, targets=(check.HOST_TARGET, "wasm32-wasip3"))
        self.assertNotEqual(declared.digest, changed.digest)
        self.assert_rejected(VALID.replace(b"wasm32-wasip2", b"wasm32-wasip3"), "GUEST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/12
    def test_normal_check_is_read_only_and_never_launches_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rust-toolchain.toml").write_bytes(VALID)
            out = io.StringIO()
            with patch.object(check, "diagnose", side_effect=AssertionError("unexpected diagnostic")), patch.object(check.subprocess, "Popen", side_effect=AssertionError("unexpected process")), redirect_stdout(out):
                code = check.main(["--root", str(root), "--format", "json"])
            result = json.loads(out.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(result["proof_ceiling"], "DECLARATION_ONLY")
            self.assertEqual(result["compilable"], "NOT_RUN")
            self.assertEqual([p.name for p in root.iterdir()], ["rust-toolchain.toml"])
            self.assertEqual((root / "rust-toolchain.toml").read_bytes(), VALID)

    # WORK_UNIT_CASE: 870/13
    def test_ambient_installation_cannot_repair_missing_declaration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rust-toolchain.toml").write_bytes(VALID.replace(b', "wasm32-wasip2"', b""))
            with patch.object(check, "diagnose", side_effect=AssertionError("must validate declaration first")), redirect_stdout(io.StringIO()):
                self.assertEqual(check.main(["--root", str(root), "--diagnostic"]), 1)

    # WORK_UNIT_CASE: 870/14
    def test_diagnostic_separates_installed_from_compilable(self):
        result, calls = self.observe()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["installed"])
        self.assertEqual(result["compilable"], "NOT_RUN")
        self.assertEqual(result["proof_ceiling"], "INSTALLED_TOOLCHAIN_ONLY")
        self.assertEqual(len(calls), 3)
        self.assertFalse(any("install" in call or "add" in call for call in calls))

    # WORK_UNIT_CASE: 870/15
    def test_probe_cannot_certify_clean_bootstrap_or_accept_missing_artifact(self):
        result, calls = self.observe(probe=True)
        self.assertTrue(result["compilable"])
        self.assertFalse(result["clean_bootstrap_qualified"])
        self.assertEqual(result["proof_ceiling"], "LOCAL_COMPONENT_COMPILE_ONLY")
        self.assertEqual(len(calls), 4)
        self.assertEqual(len(result["artifact_sha256"]), 64)
        for options in ({"artifact": False}, {"bad_header": True}, {"fail_compile": True}):
            with self.subTest(options=options):
                rejected, _ = self.observe(probe=True, **options)
                self.assertEqual(rejected["status"], "INCOMPLETE")
                self.assertFalse(rejected["compilable"])
                self.assertNotIn("secret", json.dumps(rejected))
        # These are unit fixtures, NOT the additional actual clean-environment
        # execution required by issue 870 case 15. The issue must stay open.

    # WORK_UNIT_CASE: 870/16
    def test_missing_target_blocks_before_guest_compilation(self):
        result, calls = self.observe(probe=True, missing_guest=True)
        self.assertEqual(result["reason"], "DECLARED_TARGET_NOT_INSTALLED")
        self.assertEqual(result["compilable"], "NOT_RUN")
        self.assertEqual(len(calls), 3)

    def test_malformed_duplicate_unknown_and_oversized_config_fail_closed(self):
        for raw in (b"\xff", VALID + b"channel='duplicate'\n", VALID + b"secret='canary'\n", VALID + b"\n[unowned]\nfoo=1\n"):
            with self.subTest(raw=raw[-30:]):
                with self.assertRaises(check.ToolchainError) as failure:
                    check.parse_declaration(raw)
                self.assertNotIn("canary", str(failure.exception))
        self.assert_rejected(b" " * (check.MAX_CONFIG_BYTES + 1), "CONFIG_SIZE_LIMIT")

    def test_components_profile_and_types_are_closed(self):
        for raw, code in (
            (VALID.replace(b'profile = "default"', b'profile = "minimal"'), "UNEXPECTED_PROFILE"),
            (VALID.replace(b'"rust-src"', b'"miri"'), "UNEXPECTED_COMPONENTS"),
            (VALID.replace(b'"rust-src"', b'"rust-src", "rust-src"'), "DUPLICATE_COMPONENTS"),
            (VALID.replace(b'"wasm32-wasip2"', b"true"), "INVALID_TARGETS"),
        ):
            self.assert_rejected(raw, code)

    def test_missing_and_symlinked_config_are_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(check.ToolchainError):
                check.read_declaration(root)
            (root / "target.toml").write_bytes(VALID)
            # Mock symlink observation on Windows runners lacking symlink rights.
            with patch.object(Path, "is_symlink", lambda path: path.name == "rust-toolchain.toml"):
                with self.assertRaisesRegex(check.ToolchainError, "TOOLCHAIN_NOT_REGULAR"):
                    check.read_declaration(root)

    def test_no_rustup_is_nonpassing_not_a_simulated_compile(self):
        with patch.object(check.shutil, "which", return_value=None):
            result = check.diagnose(check.parse_declaration(VALID), probe=True)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reason"], "RUSTUP_UNAVAILABLE")
        self.assertEqual(result["compilable"], "NOT_RUN")

    def test_wrong_compiler_identity_is_rejected(self):
        calls, run = self.fake_tools()
        def wrong(argv, cwd, timeout):
            if "--version" in argv:
                return check.CommandResult("OK", b"release: 1.98.0\ncommit-hash: " + b"a" * 40)
            return run(argv, cwd, timeout)
        with patch.object(check.shutil, "which", return_value="/admitted/rustup"), patch.object(check, "_run", side_effect=wrong):
            result = check.diagnose(check.parse_declaration(VALID), probe=True)
        self.assertEqual(result["reason"], "COMPILER_VERSION_MISMATCH")
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_primary_failure_survives_unknown_cleanup(self):
        captured = []
        def timeout(argv, cwd, limit):
            captured.append(cwd)
            return check.CommandResult("TOOL_TIMEOUT", cleanup_known=False)
        try:
            with patch.object(check.shutil, "which", return_value="/admitted/rustup"), patch.object(check, "_run", side_effect=timeout):
                result = check.diagnose(check.parse_declaration(VALID), probe=True)
            self.assertEqual(result["reason"], "TOOL_TIMEOUT")
            self.assertEqual(result["cleanup"], "UNKNOWN")
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertTrue(captured[0].is_dir())
        finally:
            for path in captured:
                check.shutil.rmtree(path)

    def test_runner_real_bounded_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check._run([sys.executable, "-c", "print('bounded')"], Path(directory), 5)
        self.assertEqual(result.status, "OK")
        self.assertEqual(result.output.strip(), b"bounded")

    def test_runner_output_flood_is_bounded_and_nonpassing(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(check, "MAX_TOOL_OUTPUT", 256):
            result = check._run([sys.executable, "-c", "print('x'*100000)"], Path(directory), 5)
        self.assertEqual(result.status, "TOOL_OUTPUT_LIMIT")
        self.assertFalse(result.cleanup_known)
        self.assertLessEqual(len(result.output), 256)

    def test_runner_timeout_never_claims_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check._run([sys.executable, "-c", "import time; time.sleep(30)"], Path(directory), .1)
        self.assertEqual(result.status, "TOOL_TIMEOUT")
        self.assertFalse(result.cleanup_known)

    def test_runner_missing_tool_does_not_echo_path_or_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check._run([str(Path(directory) / "absent-secret-canary")], Path(directory), 1)
        self.assertEqual(result.status, "TOOL_UNAVAILABLE")
        self.assertEqual(result.output, b"")

    def test_legacy_override_cannot_shadow_the_checked_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rust-toolchain.toml").write_bytes(VALID)
            (root / "rust-toolchain").write_text("nightly\n")
            with self.assertRaisesRegex(check.ToolchainError, "LEGACY_TOOLCHAIN_SHADOWS_TOML"):
                check.read_declaration(root)

    def test_invalid_path_and_missing_scratch_return_bounded_errors(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(check.main(["--root", "\0secret-canary", "--format", "json"]), 1)
        self.assertNotIn("secret-canary", out.getvalue())
        with patch.object(check.shutil, "which", return_value="/admitted/rustup"), patch.object(check.tempfile, "mkdtemp", side_effect=OSError("secret-canary")):
            result = check.diagnose(check.parse_declaration(VALID), probe=True)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reason"], "PROBE_IO_FAILED")
        self.assertNotIn("secret-canary", json.dumps(result))

    def test_cli_json_and_text_have_same_disposition(self):
        results = []
        for format in ("text", "json"):
            captured = io.StringIO()
            with redirect_stdout(captured):
                results.append(check.main(["--root", str(ROOT), "--format", format]))
            self.assertIn("DECLARATION_ONLY", captured.getvalue())
            self.assertIn("PASS", captured.getvalue())
        self.assertEqual(results, [0, 0])


if __name__ == "__main__":
    unittest.main()
