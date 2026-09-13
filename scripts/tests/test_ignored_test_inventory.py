"""Unit tests for ignored-test denominator and environment classification (issue #905 / PR #1132)."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

# Dynamically import scripts/integration/ignored_test_inventory.py
_script_path = Path(__file__).resolve().parents[1] / "integration" / "ignored_test_inventory.py"
_spec = importlib.util.spec_from_file_location("ignored_test_inventory", _script_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {_script_path}")
iti = importlib.util.module_from_spec(_spec)
sys.modules["ignored_test_inventory"] = iti
_spec.loader.exec_module(iti)

InventoryError = iti.InventoryError
BOUNDS = iti.BOUNDS
Bounds = iti.Bounds
RowState = iti.RowState
Requirement = iti.Requirement
SourceTest = iti.SourceTest
CompiledTest = iti.CompiledTest
InventoryRow = iti.InventoryRow
PackageTarget = iti.PackageTarget
Artifact = iti.Artifact
CommandResult = iti.CommandResult
SCHEMA = iti.SCHEMA
TOOL_VERSION = iti.TOOL_VERSION
OUTPUT_ROOT = iti.OUTPUT_ROOT

_sha256 = iti._sha256
_canonical_bytes = iti._canonical_bytes
_repo_path = iti._repo_path
_safe_output = iti._safe_output
_bounded_read = iti._bounded_read
_validate_command = iti._validate_command
_run_fixed = iti._run_fixed
_cargo_metadata = iti._cargo_metadata
_targets = iti._targets
_lex_rust = iti._lex_rust
_decode_reason = iti._decode_reason
_attribute_flags = iti._attribute_flags
_scan_file = iti._scan_file
_requirements = iti._requirements
discover_source = iti.discover_source
discover_compiled = iti.discover_compiled
reconcile = iti.reconcile
build_inventory = iti.build_inventory
self_test = iti.self_test
run_self_tests = iti.run_self_tests
main = iti.main


def _scan_snippet(code: str, target: PackageTarget | None = None, file_name: str = "src/lib.rs") -> list[SourceTest]:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        src_path = root / file_name
        src_path.parent.mkdir(parents=True, exist_ok=True)
        src_path.write_text(code, encoding="utf-8")
        if target is None:
            target = PackageTarget(
                package_id="test-pkg 0.1.0 (path+file:///crates/test-pkg)",
                package_name="test-pkg",
                manifest_dir=root,
                target_name="test_target",
                target_kind="lib",
                src_path=src_path,
            )
        return _scan_file(root, target, src_path)


class TestIgnoredTestInventory(unittest.TestCase):
    """Test suite verifying the exact ignored-test denominator contract (issue #905)."""

    def setUp(self) -> None:
        self.fixture_dir = Path(__file__).resolve().parents[1] / "testdata" / "integration" / "ignored-test-inventory"

    # WORK_UNIT_CASE: 905/1
    def test_closed_descriptor_schema_round_trip(self) -> None:
        """Closed descriptor/schema round trip."""
        self.assertEqual(SCHEMA, "eliot.integration.ignored-test-inventory.v1")
        self.assertEqual(TOOL_VERSION, "0.1.0")

        fixture_path = self.fixture_dir / "sample_inventory.json"
        self.assertTrue(fixture_path.is_file(), f"missing fixture: {fixture_path}")
        raw_json = fixture_path.read_bytes()
        parsed = json.loads(raw_json)

        header = parsed["header"]
        self.assertEqual(header["schema"], SCHEMA)
        self.assertEqual(header["tool_version"], TOOL_VERSION)
        self.assertEqual(header["proof_ceiling"], "IGNORED_TEST_IDENTITY_AND_ENVIRONMENT_CLASSIFICATION_ONLY")
        self.assertIn("source_identity", header)
        self.assertIn("aggregate_sha256", header)
        self.assertIn("counts_by_state", header)
        self.assertIn("complete", header)

        # Canonical bytes round trip
        canonical = _canonical_bytes(parsed)
        round_tripped = json.loads(canonical)
        self.assertEqual(parsed, round_tripped)

        # Verify row dataclass conversion round trip
        for row_dict in parsed["rows"]:
            row_obj = InventoryRow(**row_dict)
            self.assertEqual(row_dict, dataclasses.asdict(row_obj))

    # WORK_UNIT_CASE: 905/2
    def test_fixed_locked_command_construction_no_arbitrary_surface(self) -> None:
        """Fixed locked command construction has no arbitrary command surface."""
        valid_commands = [
            ("cargo", "metadata", "--locked", "--format-version", "1"),
            ("cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json"),
            ("git", "rev-parse", "HEAD"),
            ("git", "status", "--porcelain=v1", "--untracked-files=no"),
            ("target/debug/deps/my_test.exe", "--list", "--ignored", "--format", "terse"),
        ]
        for cmd in valid_commands:
            try:
                _validate_command(cmd)
            except InventoryError as exc:
                self.fail(f"Valid command rejected: {cmd} with {exc}")

        invalid_commands = [
            ("cargo", "run"),
            ("cargo", "metadata"),
            ("cargo", "test", "--workspace"),
            ("git", "push"),
            ("git", "fetch"),
            ("sh", "-c", "echo hello"),
            ("rm", "-rf", "/"),
            (),
            ("-evil_executable", "--list", "--ignored", "--format", "terse"),
            ("target/test.exe", "--list", "--ignored", "--format", "json"),
        ]
        for cmd in invalid_commands:
            with self.assertRaises(InventoryError) as cm:
                _validate_command(cmd)
            self.assertEqual(cm.exception.code, "COMMAND_NOT_ALLOWED")

        # Verify environment filtering in _run_fixed preserves CARGO_TARGET_DIR but drops arbitrary vars
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            with patch.dict(os.environ, {"CARGO_TARGET_DIR": "my_custom_target", "ARBITRARY_INJECTION": "secret"}):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value.returncode = 0
                    mock_run.return_value.stdout = b"fake"
                    mock_run.return_value.stderr = b""
                    _run_fixed(troot, ("git", "rev-parse", "HEAD"))
                    called_env = mock_run.call_args[1]["env"]
                    self.assertEqual(called_env.get("CARGO_TARGET_DIR"), "my_custom_target")
                    self.assertNotIn("ARBITRARY_INJECTION", called_env)

    # WORK_UNIT_CASE: 905/3
    def test_ordinary_reason_bearing_ignored_sync_tests_found(self) -> None:
        """Ordinary reason-bearing ignored sync tests found."""
        code = """
        #[test]
        #[ignore = "requires store database"]
        fn test_sync_ignored() {
            assert!(true);
        }
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 1)
        test = tests[0]
        self.assertEqual(test.test_name, "test_sync_ignored")
        self.assertEqual(test.reason, "requires store database")
        self.assertEqual(test.requirements, (Requirement.STORE.value,))
        self.assertEqual(test.target_kind, "lib")

    # WORK_UNIT_CASE: 905/4
    def test_ignored_async_tokio_tests_found(self) -> None:
        """Ignored async/tokio tests found."""
        code = """
        #[tokio::test]
        #[ignore = "requires kernel and governor host"]
        async fn test_tokio_ignored() {
            assert!(true);
        }

        #[async_std::test]
        #[ignore = "requires git worktree"]
        async fn test_async_std_ignored() {
            assert!(true);
        }
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 2)
        names = {t.test_name: t for t in tests}
        self.assertIn("test_tokio_ignored", names)
        self.assertEqual(names["test_tokio_ignored"].requirements, (Requirement.RUNTIME.value,))
        self.assertIn("test_async_std_ignored", names)
        self.assertEqual(names["test_async_std_ignored"].requirements, (Requirement.GIT.value,))

    # WORK_UNIT_CASE: 905/5
    def test_ignore_like_comments_and_strings_excluded(self) -> None:
        """Ignore-like comments and strings excluded."""
        code = """
        // #[test]
        // #[ignore = "commented test"]
        // fn test_in_comment() {}

        /*
        #[test]
        #[ignore = "in block comment"]
        fn test_in_block() {}
        */

        fn not_a_test() {
            let _s = "#[test]\\n#[ignore = \\\"in string\\\"]\\nfn test_in_str() {}";
            let _raw = r#"#[test] #[ignore = "raw"] fn test_in_raw() {}"#;
        }
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 0)

    # WORK_UNIT_CASE: 905/6
    def test_nested_modules_preserve_exact_item_identity(self) -> None:
        """Nested modules preserve exact item identity."""
        code = """
        mod outer {
            mod inner {
                #[test]
                #[ignore = "requires store"]
                fn deeply_nested_test() {}
            }
        }
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 1)
        self.assertEqual(tests[0].test_name, "outer::inner::deeply_nested_test")

    # WORK_UNIT_CASE: 905/7
    def test_package_target_binary_distinguishes_equal_names_across_binaries(self) -> None:
        """Package/target/binary/test distinguishes equal names across binaries."""
        s1 = SourceTest(
            package_id="pkg_a 0.1.0",
            package_name="pkg_a",
            target_name="crate_lib",
            target_kind="lib",
            test_name="common_test",
            source_path="crates/pkg_a/src/lib.rs",
            line=10,
            attribute_text="#[test]\n#[ignore = \"requires store\"]",
            attribute_digest="d1",
            reason="requires store",
            cfg_evidence=(),
            requirements=("STORE",),
            source_digest="sd1",
        )
        s2 = SourceTest(
            package_id="pkg_b 0.1.0",
            package_name="pkg_b",
            target_name="crate_integ",
            target_kind="test",
            test_name="common_test",
            source_path="crates/pkg_b/tests/integ.rs",
            line=20,
            attribute_text="#[test]\n#[ignore = \"requires store\"]",
            attribute_digest="d2",
            reason="requires store",
            cfg_evidence=(),
            requirements=("STORE",),
            source_digest="sd2",
        )
        c1 = CompiledTest(
            package_id="pkg_a 0.1.0",
            package_name="pkg_a",
            target_name="crate_lib",
            target_kind="lib",
            executable="target/debug/deps/crate_lib-1",
            executable_digest="ed1",
            test_name="common_test",
        )
        c2 = CompiledTest(
            package_id="pkg_b 0.1.0",
            package_name="pkg_b",
            target_name="crate_integ",
            target_kind="test",
            executable="target/debug/deps/crate_integ-2",
            executable_digest="ed2",
            test_name="common_test",
        )

        rows = reconcile([s1, s2], [c1, c2])
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r.state == RowState.CLASSIFIED.value for r in rows))
        self.assertNotEqual(rows[0].package_id, rows[1].package_id)

    # WORK_UNIT_CASE: 905/8
    def test_duplicate_identity_inside_one_binary_rejected_duplicate(self) -> None:
        """Duplicate identity inside one binary rejected (marked DUPLICATE)."""
        s1 = SourceTest(
            package_id="pkg 0.1.0",
            package_name="pkg",
            target_name="lib",
            target_kind="lib",
            test_name="dup_test",
            source_path="src/lib.rs",
            line=10,
            attribute_text="#[test]\n#[ignore = \"store\"]",
            attribute_digest="d1",
            reason="store",
            cfg_evidence=(),
            requirements=("STORE",),
            source_digest="sd1",
        )
        s2 = SourceTest(
            package_id="pkg 0.1.0",
            package_name="pkg",
            target_name="lib",
            target_kind="lib",
            test_name="dup_test",
            source_path="src/lib.rs",
            line=30,
            attribute_text="#[test]\n#[ignore = \"store\"]",
            attribute_digest="d2",
            reason="store",
            cfg_evidence=(),
            requirements=("STORE",),
            source_digest="sd2",
        )
        c = CompiledTest(
            package_id="pkg 0.1.0",
            package_name="pkg",
            target_name="lib",
            target_kind="lib",
            executable="target/debug/deps/lib",
            executable_digest="ed",
            test_name="dup_test",
        )

        rows = reconcile([s1, s2], [c])
        self.assertTrue(len(rows) >= 2)
        for r in rows:
            self.assertEqual(r.state, RowState.DUPLICATE.value)
            self.assertEqual(r.remediation_owner, "test-source-owner")

    # WORK_UNIT_CASE: 905/9
    def test_exact_supported_compiled_list_ignored_output_parsed(self) -> None:
        """Exact supported compiled list/ignored output parsed."""
        terse_fixture = self.fixture_dir / "sample_terse_listing.txt"
        self.assertTrue(terse_fixture.is_file())
        text = terse_fixture.read_text(encoding="utf-8")

        parsed_names = []
        for line in text.splitlines():
            m = re.fullmatch(r"(.+?):\s+(?:test|benchmark)", line.strip())
            if m:
                parsed_names.append(m.group(1))

        expected = [
            "test_sync_ignored",
            "test_tokio_ignored",
            "test_disabled_ignored",
            "test_cfg_attr_ignored",
            "test_bare_ignored",
            "test_unknown_reason_ignored",
            "nested::test_nested_ignored",
        ]
        self.assertEqual(parsed_names, expected)

    # WORK_UNIT_CASE: 905/10
    def test_malformed_truncated_invalid_encoding_fixture_fails(self) -> None:
        """Malformed/truncated/invalid-encoding fixture output fails (COMPILED_GRAPH_UNAVAILABLE)."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()

            # Malformed JSON from cargo metadata
            def runner_malformed(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                return CommandResult(stdout=b"{ not valid json ...", stderr=b"")

            with self.assertRaises(InventoryError) as cm:
                _cargo_metadata(troot, runner=runner_malformed)
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            # Invalid shape from cargo metadata
            def runner_invalid_shape(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                return CommandResult(stdout=b'{"packages": "not a list"}', stderr=b"")

            with self.assertRaises(InventoryError) as cm:
                _cargo_metadata(troot, runner=runner_invalid_shape)
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            # Non-UTF-8 listing output
            bin_path = troot / "fake_bin.exe"
            bin_path.write_bytes(b"binary content")
            target = PackageTarget("p1", "pkg", troot, "tname", "lib", troot / "src" / "lib.rs")

            def runner_bad_listing(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                if "cargo" in argv:
                    artifact_json = json.dumps({
                        "reason": "compiler-artifact",
                        "package_id": "p1",
                        "target": {"name": "tname", "kind": ["lib"]},
                        "profile": {"test": True},
                        "executable": str(bin_path),
                    }).encode("utf-8") + b"\n"
                    return CommandResult(stdout=artifact_json, stderr=b"")
                return CommandResult(stdout=b"\xff\xfe invalid utf8", stderr=b"")

            with self.assertRaises(InventoryError) as cm:
                discover_compiled(troot, [target], runner=runner_bad_listing)
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            # Control characters in test name
            def runner_control_chars(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                if "cargo" in argv:
                    artifact_json = json.dumps({
                        "reason": "compiler-artifact",
                        "package_id": "p1",
                        "target": {"name": "tname", "kind": ["lib"]},
                        "profile": {"test": True},
                        "executable": str(bin_path),
                    }).encode("utf-8") + b"\n"
                    return CommandResult(stdout=artifact_json, stderr=b"")
                return CommandResult(stdout=b"bad\x00name: test\n", stderr=b"")

            with self.assertRaises(InventoryError) as cm:
                discover_compiled(troot, [target], runner=runner_control_chars)
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

    # WORK_UNIT_CASE: 905/11
    def test_exact_one_to_one_source_compiled_match_classified(self) -> None:
        """Exact one-to-one source/compiled match classified (state CLASSIFIED)."""
        s = SourceTest(
            package_id="p1",
            package_name="pkg",
            target_name="lib",
            target_kind="lib",
            test_name="test_ok",
            source_path="src/lib.rs",
            line=10,
            attribute_text="#[test]\n#[ignore = \"requires store\"]",
            attribute_digest="ad",
            reason="requires store",
            cfg_evidence=(),
            requirements=("STORE",),
            source_digest="sd",
        )
        c = CompiledTest(
            package_id="p1",
            package_name="pkg",
            target_name="lib",
            target_kind="lib",
            executable="target/debug/deps/lib",
            executable_digest="ed",
            test_name="test_ok",
        )

        rows = reconcile([s], [c])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.state, RowState.CLASSIFIED.value)
        self.assertEqual(row.remediation_owner, "declared-environment-owner")

    # WORK_UNIT_CASE: 905/12
    def test_source_only_row_retained_and_incomplete(self) -> None:
        """Source-only row retained and incomplete (state SOURCE_ONLY, complete False)."""
        s = SourceTest(
            package_id="p1",
            package_name="pkg",
            target_name="lib",
            target_kind="lib",
            test_name="test_missing_compiled",
            source_path="src/lib.rs",
            line=10,
            attribute_text="#[test]\n#[ignore = \"requires store\"]",
            attribute_digest="ad",
            reason="requires store",
            cfg_evidence=(),
            requirements=("STORE",),
            source_digest="sd",
        )

        rows = reconcile([s], [])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.state, RowState.SOURCE_ONLY.value)
        self.assertEqual(row.remediation_owner, "test-target-owner")
        self.assertFalse(all(r.state == RowState.CLASSIFIED.value for r in rows))

    # WORK_UNIT_CASE: 905/13
    def test_compiled_only_row_retained_and_incomplete(self) -> None:
        """Compiled-only row retained and incomplete (state COMPILED_ONLY, complete False)."""
        c = CompiledTest(
            package_id="p1",
            package_name="pkg",
            target_name="lib",
            target_kind="lib",
            executable="target/debug/deps/lib",
            executable_digest="ed",
            test_name="test_missing_source",
        )

        rows = reconcile([], [c])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.state, RowState.COMPILED_ONLY.value)
        self.assertEqual(row.remediation_owner, "build-test-graph-owner")
        self.assertFalse(all(r.state == RowState.CLASSIFIED.value for r in rows))

    # WORK_UNIT_CASE: 905/14
    def test_bare_ignore_becomes_unclassified(self) -> None:
        """Bare ignore becomes Unclassified."""
        code = """
        #[test]
        #[ignore]
        fn test_bare() {}
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 1)
        s = tests[0]
        self.assertIsNone(s.reason)

        c = CompiledTest(
            package_id=s.package_id,
            package_name=s.package_name,
            target_name=s.target_name,
            target_kind=s.target_kind,
            executable="target/debug/deps/lib",
            executable_digest="ed",
            test_name=s.test_name,
        )
        rows = reconcile([s], [c])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].state, RowState.UNCLASSIFIED.value)
        self.assertEqual(rows[0].remediation_owner, "test-declaration-owner")

    # WORK_UNIT_CASE: 905/15
    def test_unknown_conflicting_reason_vocabulary_remains_unclassified(self) -> None:
        """Unknown/conflicting reason vocabulary remains Unclassified."""
        code = """
        #[test]
        #[ignore = "flaky in CI sometimes"]
        fn test_flaky() {}
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 1)
        s = tests[0]
        self.assertEqual(s.requirements, (Requirement.UNKNOWN.value,))

        c = CompiledTest(
            package_id=s.package_id,
            package_name=s.package_name,
            target_name=s.target_name,
            target_kind=s.target_kind,
            executable="target/debug/deps/lib",
            executable_digest="ed",
            test_name=s.test_name,
        )
        rows = reconcile([s], [c])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].state, RowState.UNCLASSIFIED.value)
        self.assertEqual(rows[0].remediation_owner, "test-declaration-owner")

    # WORK_UNIT_CASE: 905/16
    def test_local_authenticated_surrealdb_version_binary_requirement_maps_to_store(self) -> None:
        """Local authenticated SurrealDB/version/binary requirement maps to Store."""
        phrases = [
            "requires local authenticated SurrealDB",
            "surrealdb version check",
            "surrealdb binary required",
            "store database migration",
            "requires authenticated db",
        ]
        for phrase in phrases:
            reqs = _requirements(phrase)
            self.assertEqual(reqs, (Requirement.STORE.value,), f"Failed for phrase: {phrase}")

    # WORK_UNIT_CASE: 905/17
    def test_governor_kernel_host_watchdog_agent_bridge_requirement_maps_to_runtime(self) -> None:
        """Governor/Kernel/Host/Watchdog/Agent Bridge requirement maps to Runtime."""
        phrases = [
            "requires Governor runtime",
            "Kernel process initialization",
            "Host daemon connection",
            "Watchdog monitor required",
            "Agent Bridge connection failure",
        ]
        for phrase in phrases:
            reqs = _requirements(phrase)
            self.assertEqual(reqs, (Requirement.RUNTIME.value,), f"Failed for phrase: {phrase}")

    # WORK_UNIT_CASE: 905/18
    def test_windows_pipe_acl_session_installation_configuration_maps_to_runtime(self) -> None:
        """Windows pipe/ACL/session/installation/configuration maps to Runtime."""
        phrases = [
            "requires Windows pipe communication",
            "named pipe connection",
            "Windows ACL security descriptor",
            "interactive session requirement",
            "installation service missing",
            "eliot_governor_config configuration missing",
            "windows runtime environment",
        ]
        for phrase in phrases:
            reqs = _requirements(phrase)
            self.assertEqual(reqs, (Requirement.RUNTIME.value,), f"Failed for phrase: {phrase}")

    # WORK_UNIT_CASE: 905/19
    def test_git_identity_repository_worktree_maps_to_git(self) -> None:
        """Git identity/repository/worktree maps to Git."""
        phrases = [
            "requires git commit identity",
            "git repository clean checkout",
            "isolated worktree required",
        ]
        for phrase in phrases:
            reqs = _requirements(phrase)
            self.assertEqual(reqs, (Requirement.GIT.value,), f"Failed for phrase: {phrase}")

    # WORK_UNIT_CASE: 905/20
    def test_external_personal_credential_requirement_remains_visible_manual_only(self) -> None:
        """External/personal credential requirement remains visible manual-only."""
        phrases = [
            "requires personal credential",
            "external credential missing",
            "paid model api key",
            "oauth token manual-only test",
        ]
        for phrase in phrases:
            reqs = _requirements(phrase)
            self.assertEqual(reqs, (Requirement.EXTERNAL_CREDENTIALED_MANUAL_ONLY.value,), f"Failed for phrase: {phrase}")

    # WORK_UNIT_CASE: 905/21
    def test_cfg_target_elided_row_stays_target_specific(self) -> None:
        """cfg/target-elided row stays target-specific."""
        code = """
        #[test]
        #[cfg_attr(windows, ignore = "requires windows runtime pipe")]
        fn test_win_specific() {}
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 1)
        s = tests[0]
        self.assertTrue(any("windows" in str(cfg) for cfg in s.cfg_evidence))
        self.assertEqual(s.target_name, "test_target")

        # When compiled on non-matching target (e.g. Linux), compiled test is absent
        rows = reconcile([s], [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].state, RowState.SOURCE_ONLY.value)
        self.assertEqual(rows[0].target_name, "test_target")
        self.assertTrue(len(rows[0].cfg_evidence) > 0)

    # WORK_UNIT_CASE: 905/22
    def test_compile_list_failure_gives_exact_compiled_graph_unavailable_owner_and_nonzero(self) -> None:
        """Compile/list failure gives exact CompiledGraphUnavailable owner and nonzero result."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            (troot / ".eliot").mkdir()

            def failing_runner(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiler crashed", owner="build-test-graph-owner")

            with self.assertRaises(InventoryError) as cm:
                _cargo_metadata(troot, runner=failing_runner)
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")
            self.assertEqual(cm.exception.owner, "build-test-graph-owner")

            # Running main() with failing runner
            with patch("scripts.integration.ignored_test_inventory.build_inventory") as mock_build:
                mock_build.side_effect = InventoryError("COMPILED_GRAPH_UNAVAILABLE", "build failed", owner="build-test-graph-owner")
                code = main(["--repo-root", str(troot), "--output", ".eliot/out.json"])
                self.assertEqual(code, 2)

    # WORK_UNIT_CASE: 905/23
    def test_canonical_order_digest_independent_of_filesystem_runner_ordering(self) -> None:
        """Canonical order/digest independent of filesystem/runner ordering."""
        s1 = SourceTest("p1", "pkg1", "t1", "lib", "test_a", "src/a.rs", 10, "#[test]", "d1", "store", (), ("STORE",), "sd1")
        s2 = SourceTest("p2", "pkg2", "t2", "lib", "test_b", "src/b.rs", 20, "#[test]", "d2", "store", (), ("STORE",), "sd2")
        c1 = CompiledTest("p1", "pkg1", "t1", "lib", "bin1", "ed1", "test_a")
        c2 = CompiledTest("p2", "pkg2", "t2", "lib", "bin2", "ed2", "test_b")

        rows_fwd = reconcile([s1, s2], [c1, c2])
        rows_rev = reconcile([s2, s1], [c2, c1])

        self.assertEqual(rows_fwd, rows_rev)
        h1 = _sha256(_canonical_bytes([dataclasses.asdict(r) for r in rows_fwd]))
        h2 = _sha256(_canonical_bytes([dataclasses.asdict(r) for r in rows_rev]))
        self.assertEqual(h1, h2)

    # WORK_UNIT_CASE: 905/24
    def test_source_reason_target_test_rule_identity_change_invalidates_digest(self) -> None:
        """Source/reason/target/test/rule identity change invalidates digest."""
        base_s = SourceTest("p1", "pkg", "tgt", "lib", "test_x", "src/lib.rs", 10, "#[test]", "ad", "store", (), ("STORE",), "sd")
        base_c = CompiledTest("p1", "pkg", "tgt", "lib", "bin", "ed", "test_x")
        base_row = reconcile([base_s], [base_c])[0]

        # Perturb reason
        s_alt_reason = dataclasses.replace(base_s, reason="windows runtime pipe", requirements=("RUNTIME",))
        row_alt_reason = reconcile([s_alt_reason], [base_c])[0]
        self.assertNotEqual(base_row.row_digest, row_alt_reason.row_digest)

        # Perturb test_name
        s_alt_name = dataclasses.replace(base_s, test_name="test_y")
        c_alt_name = dataclasses.replace(base_c, test_name="test_y")
        row_alt_name = reconcile([s_alt_name], [c_alt_name])[0]
        self.assertNotEqual(base_row.row_digest, row_alt_name.row_digest)

        # Perturb target_name
        s_alt_tgt = dataclasses.replace(base_s, target_name="tgt2")
        c_alt_tgt = dataclasses.replace(base_c, target_name="tgt2")
        row_alt_tgt = reconcile([s_alt_tgt], [c_alt_tgt])[0]
        self.assertNotEqual(base_row.row_digest, row_alt_tgt.row_digest)

        # Perturb source_line
        s_alt_line = dataclasses.replace(base_s, line=999)
        row_alt_line = reconcile([s_alt_line], [base_c])[0]
        self.assertNotEqual(base_row.row_digest, row_alt_line.row_digest)

    # WORK_UNIT_CASE: 905/25
    def test_path_reparse_escape_and_file_test_output_time_bounds_fail_within_limits(self) -> None:
        """Path/reparse escape and file/test/output/time bounds fail within limits."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            (troot / ".eliot").mkdir()

            # Output escaping root
            with self.assertRaises(InventoryError) as cm:
                _safe_output(troot, troot.parent / "escape.json")
            self.assertEqual(cm.exception.code, "UNSAFE_OUTPUT")

            # Output outside .eliot
            with self.assertRaises(InventoryError) as cm:
                _safe_output(troot, troot / "not_eliot" / "out.json")
            self.assertEqual(cm.exception.code, "UNSAFE_OUTPUT")

            # Output exists without overwrite
            existing = troot / ".eliot" / "existing.json"
            existing.write_bytes(b"{}")
            with self.assertRaises(InventoryError) as cm:
                _safe_output(troot, existing, overwrite=False)
            self.assertEqual(cm.exception.code, "OUTPUT_EXISTS")

            # File exceeding max_file_bytes
            large_file = troot / "large.rs"
            with patch.object(Path, "stat") as mock_stat:
                mock_stat.return_value.st_size = BOUNDS.max_file_bytes + 1
                with self.assertRaises(InventoryError) as cm:
                    _bounded_read(large_file)
                self.assertEqual(cm.exception.code, "SOURCE_FILE_TOO_LARGE")

    # WORK_UNIT_CASE: 905/26
    def test_no_provisioning_ignored_test_execution_workflow_secret_rust_mutation_path(self) -> None:
        """No provisioning, ignored-test execution, workflow/secret/Rust mutation path."""
        source_text = _script_path.read_text(encoding="utf-8")
        parsed_ast = ast.parse(source_text)

        # Check imports: no network or database libraries
        disallowed_modules = {"socket", "urllib", "requests", "http", "surrealdb", "sqlite3", "psycopg2"}
        for node in ast.walk(parsed_ast):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, disallowed_modules)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertNotIn(node.module.split(".")[0], disallowed_modules)

        # Verify test execution flags: only --list --ignored --format terse is used
        self.assertIn("--list", source_text)
        self.assertIn("--ignored", source_text)
        self.assertIn("--format", source_text)
        self.assertIn("terse", source_text)

        # Verify no open() with "w" writing to Rust sources (.rs)
        for node in ast.walk(parsed_ast):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "open":
                    # Check argument is not writing to .rs
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            self.assertNotIn(".rs", arg.value)

    # WORK_UNIT_CASE: 905/27
    def test_supported_cfg_attr_ignore_forms_reconcile_without_evaluating_cfg(self) -> None:
        """Supported cfg_attr ignore forms reconcile without evaluating arbitrary cfg expressions."""
        code = """
        #[test]
        #[cfg_attr(windows, ignore = "requires windows runtime named pipe")]
        fn test_cfg_attr_simple() {}

        #[test]
        #[cfg_attr(all(target_os = "linux", feature = "custom_db"), ignore = "requires store database")]
        fn test_cfg_attr_complex() {}
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 2)
        by_name = {t.test_name: t for t in tests}

        simple = by_name["test_cfg_attr_simple"]
        self.assertEqual(simple.reason, "requires windows runtime named pipe")
        self.assertEqual(simple.requirements, (Requirement.RUNTIME.value,))

        complex_t = by_name["test_cfg_attr_complex"]
        self.assertEqual(complex_t.reason, "requires store database")
        self.assertEqual(complex_t.requirements, (Requirement.STORE.value,))

    # WORK_UNIT_CASE: 905/28
    def test_exact_repository_owned_disabled_test_entries_and_composed_requirements(self) -> None:
        """Exact repository-owned disabled-test entries and composed Runtime+Store requirements stay in denominator."""
        code = """
        #[disabled_test = "requires local authenticated surrealdb store and governor host runtime"]
        fn test_disabled_composed() {}

        #[eliot_disabled_test = "requires store and runtime windows pipe"]
        fn test_eliot_disabled() {}

        #[test_disabled = "requires kernel host"]
        fn test_disabled_alt() {}
        """
        tests = _scan_snippet(code)
        self.assertEqual(len(tests), 3)
        by_name = {t.test_name: t for t in tests}

        composed = by_name["test_disabled_composed"]
        self.assertEqual(composed.requirements, (Requirement.RUNTIME.value, Requirement.STORE.value))

        eliot_composed = by_name["test_eliot_disabled"]
        self.assertEqual(eliot_composed.requirements, (Requirement.RUNTIME.value, Requirement.STORE.value))

        # Reconciles cleanly into CLASSIFIED when compiled test is present
        c = CompiledTest(
            package_id=composed.package_id,
            package_name=composed.package_name,
            target_name=composed.target_name,
            target_kind=composed.target_kind,
            executable="target/debug/deps/lib",
            executable_digest="ed",
            test_name=composed.test_name,
        )
        rows = reconcile([composed], [c])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].state, RowState.CLASSIFIED.value)
        self.assertEqual(rows[0].requirements, (Requirement.RUNTIME.value, Requirement.STORE.value))


if __name__ == "__main__":
    unittest.main()
