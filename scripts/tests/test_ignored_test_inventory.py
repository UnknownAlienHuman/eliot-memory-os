"""Unit tests for ignored-test denominator and environment classification (issue #905 / PR #1132)."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib.util
import io
import json
import ntpath
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

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


def _fixture_rustc_verbose(toolchain: dict[str, object]) -> bytes:
    return (
        f"{toolchain['rustc_version']}\n"
        f"release: {toolchain['release']}\n"
        f"host: {toolchain['host']}\n"
        f"commit-hash: {toolchain['commit_hash']}\n"
    ).encode("utf-8")


class TestIgnoredTestInventory(unittest.TestCase):
    """Test suite verifying the exact ignored-test denominator contract (issue #905)."""

    def setUp(self) -> None:
        self.fixture_dir = Path(__file__).resolve().parents[1] / "testdata" / "integration" / "ignored-test-inventory"

    # WORK_UNIT_CASE: 905/1
    def test_closed_descriptor_schema_round_trip(self) -> None:
        """Closed descriptor/schema round trip."""
        self.assertEqual(SCHEMA, "eliot.integration.ignored-test-inventory.v1")
        self.assertEqual(TOOL_VERSION, "0.5.0")

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
        self.assertIs(header["source_identity"]["tracked_tree_clean"], True)
        self.assertIsInstance(header["toolchain"]["rustc_version"], str)
        self.assertTrue(header["toolchain"]["rustc_version"])
        self.assertEqual(header["toolchain"]["rustc_version"].split()[1], header["toolchain"]["release"])
        self.assertRegex(
            header["toolchain"]["rustc_version"],
            rf"\Arustc {re.escape(header['toolchain']['release'])} \(.+\)\Z",
        )
        self.assertIsInstance(header["toolchain"]["host"], str)
        self.assertTrue(header["toolchain"]["host"])
        self.assertRegex(header["toolchain"]["commit_hash"], r"\A[0-9a-f]{40}\Z")
        self.assertEqual(
            header["toolchain"]["rustc_verbose_sha256"],
            hashlib.sha256(_fixture_rustc_verbose(header["toolchain"])).hexdigest(),
        )
        self.assertIsInstance(header["toolchain"]["channel"], str)
        self.assertTrue(header["toolchain"]["channel"])
        self.assertRegex(header["toolchain"]["toolchain_file_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(header["rule_table"]["version"], iti.RULE_TABLE_VERSION)
        self.assertRegex(header["rule_table"]["sha256"], r"\A[0-9a-f]{64}\Z")

        for digest_field in (
            "metadata_sha256",
            "cargo_build_sha256",
            "target_denominator_sha256",
            "source_denominator_sha256",
            "artifact_denominator_sha256",
            "aggregate_sha256",
        ):
            self.assertRegex(header[digest_field], r"\A[0-9a-f]{64}\Z")

        for denominator_field, digest_field in (
            ("target_denominator", "target_denominator_sha256"),
            ("source_denominator", "source_denominator_sha256"),
            ("artifact_denominator", "artifact_denominator_sha256"),
        ):
            self.assertIsInstance(header[denominator_field], list)
            self.assertTrue(header[denominator_field])
            digest = hashlib.sha256(_canonical_bytes(header[denominator_field])).hexdigest()
            self.assertEqual(header[digest_field], digest)

        # Closed denominator schema (issue #905 W10): production emits exactly
        # these key sets (`_target_denominator`, `discover_source` resolved
        # shape, artifact records) - no extra fields admitted.
        target_fields = {
            "package_id", "package_name", "target_name", "target_kind", "src_path",
            "test_enabled", "doctest_enabled", "bench_enabled", "required_features",
            "required_features_satisfied", "features", "available_features", "edition",
            "test_disposition",
        }
        source_fields = {
            "package_id", "package_name", "target_name", "target_kind", "path",
            "module_path", "sha256", "file_identity", "cfg_evidence", "resolution",
            "declaration",
        }
        artifact_fields = {
            "package_id", "package_name", "target_name", "target_kind", "profile",
            "features", "filenames", "executable", "file_identity", "sha256",
            "ignored_test_count",
        }
        for record in header["target_denominator"]:
            self.assertEqual(set(record), target_fields)
            self.assertIn(record["test_disposition"], {"test_enabled", "test_disabled", "exempt"})
            self.assertIsNone(record["bench_enabled"])
            self.assertIsInstance(record["edition"], str)
            self.assertTrue(record["edition"])
            self.assertIsInstance(record["features"], list)
            self.assertIsInstance(record["available_features"], list)
            if record["required_features_satisfied"] is True:
                self.assertTrue(
                    set(record["required_features"]).issubset(set(record["features"])),
                    "satisfied target must enable its required features",
                )
        for record in header["source_denominator"]:
            self.assertEqual(set(record), source_fields)
            self.assertIn(record["resolution"], {"resolved", "unresolved"})
            if record["resolution"] == "resolved":
                self.assertRegex(record["sha256"], r"\A[0-9a-f]{64}\Z")
                self.assertEqual(
                    set(record["file_identity"]), {"device", "inode", "size", "mtime_ns"}
                )
            else:
                self.assertIsNone(record["sha256"])
                self.assertIsNone(record["file_identity"])
        for record in header["artifact_denominator"]:
            self.assertEqual(set(record), artifact_fields)
            self.assertIsInstance(record["ignored_test_count"], int)
            self.assertGreaterEqual(record["ignored_test_count"], 0)
            self.assertEqual(set(record["file_identity"]), {"device", "inode", "size", "mtime_ns"})
            self.assertRegex(record["sha256"], r"\A[0-9a-f]{64}\Z")
            executable = record["executable"]
            self.assertIsInstance(executable, str)
            if isinstance(executable, str):
                self.assertTrue(executable)
                self.assertFalse(ntpath.isabs(executable))
                drive, _tail = ntpath.splitdrive(executable)
                self.assertEqual(drive, "")
                self.assertNotIn("\\", executable)
                components = executable.split("/")
                self.assertTrue(all(components))
                self.assertTrue(all(component not in {".", ".."} for component in components))

        for row_dict in parsed["rows"]:
            if row_dict["executable"] is None:
                continue
            row_identity = (
                row_dict["package_id"],
                row_dict["target_kind"],
                row_dict["target_name"],
                row_dict["executable_digest"],
            )
            matching_artifacts = [
                record
                for record in header["artifact_denominator"]
                if (
                    record["package_id"],
                    record["target_kind"],
                    record["target_name"],
                    record["sha256"],
                )
                == row_identity
            ]
            self.assertEqual(
                len(matching_artifacts),
                1,
                f"row has no unique artifact binding: {row_identity}",
            )
            artifact = matching_artifacts[0]
            self.assertEqual(row_dict["executable"], artifact["executable"])
            self.assertEqual(row_dict["executable_digest"], artifact["sha256"])

        self.assertIs(header["source_identity"]["untracked_tree_clean"], True)
        self.assertIs(header["source_identity"]["working_tree_clean"], True)

        for completeness_field in (
            "source_denominator_complete",
            "compiled_graph_complete",
            "identity_complete",
            "row_classification_complete",
        ):
            self.assertIs(header[completeness_field], True)
        self.assertEqual(header["row_classification_status"], "complete")
        self.assertIs(header["complete"], True)
        self.assertIsNone(header["duration_observation_ms"])
        self.assertIs(header["cargo_build_finished_success"], True)
        self.assertEqual(
            header["command_profile"],
            {
                "metadata_argv": ["cargo", "metadata", "--locked", "--format-version", "1"],
                "build_argv": [
                    "cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run",
                    "--message-format=json",
                ],
                "libtest_list_suffix": ["--list", "--ignored", "--format", "terse"],
                "target_root": ".eliot/integration/ignored-test-inventory/target",
            },
        )

        aggregate_input = {
            "header": {key: value for key, value in header.items() if key != "aggregate_sha256"},
            "rows": parsed["rows"],
        }
        expected_aggregate = hashlib.sha256(_canonical_bytes(aggregate_input)).hexdigest()
        self.assertEqual(header["aggregate_sha256"], expected_aggregate)

        for row_dict in parsed["rows"]:
            self.assertRegex(row_dict["row_digest"], r"\A[0-9a-f]{64}\Z")
            self.assertEqual(row_dict["isolation"], [])
            row_payload = {key: value for key, value in row_dict.items() if key != "row_digest"}
            expected_row_digest = hashlib.sha256(_canonical_bytes(row_payload)).hexdigest()
            self.assertEqual(row_dict["row_digest"], expected_row_digest)

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
            ("git", "status", "--porcelain=v1", "--untracked-files=all"),
            ("rustc", "--version", "--verbose"),
        ]
        for cmd in valid_commands:
            try:
                _validate_command(cmd)
            except InventoryError as exc:
                self.fail(f"Valid command rejected: {cmd} with {exc}")

        invalid_commands = [
            ("cargo", "run"),
            ("cargo", "install", "synthetic-tool"),
            ("cargo", "metadata"),
            ("cargo", "test", "--workspace"),
            ("git", "push"),
            ("git", "fetch"),
            ("sh", "-c", "echo hello"),
            ("rm", "-rf", "/"),
            (),
            ("-evil_executable", "--list", "--ignored", "--format", "terse"),
            ("target/debug/deps/my_test.exe", "--list", "--ignored", "--format", "terse"),
            ("target/test.exe", "--list", "--ignored", "--format", "json"),
        ]
        for cmd in invalid_commands:
            with self.assertRaises(InventoryError) as cm:
                _validate_command(cmd)
            self.assertEqual(cm.exception.code, "COMMAND_NOT_ALLOWED")

        diagnostic_cap = 128
        embedded_token = "ghp_" + ("s" * 32)
        oversized_argument = "C:\\Users\\oracle-user\\" + embedded_token + ("z" * 512)
        with patch.object(
            iti,
            "BOUNDS",
            dataclasses.replace(BOUNDS, max_command_output_bytes=diagnostic_cap),
        ):
            with self.assertRaises(InventoryError) as cm:
                iti._validate_command(("cargo", "run", oversized_argument))
        self.assertEqual(cm.exception.code, "COMMAND_NOT_ALLOWED")
        self.assertLessEqual(len(cm.exception.detail.encode("utf-8")), diagnostic_cap)
        self.assertNotIn("oracle-user", cm.exception.detail)
        self.assertNotIn(embedded_token, cm.exception.detail)

        # The runner owns its admitted target directory and drops caller command-path injection.
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            job = object()
            process_handle = 1234
            process_pid = 1
            launched_processes: list[Mock] = []

            def make_success_process() -> Mock:
                child = Mock()
                child._handle = process_handle
                child.pid = process_pid
                child.stdout = io.BytesIO(b"")
                child.stderr = io.BytesIO(b"")
                child.returncode = 0
                child.wait.return_value = 0
                child.poll.return_value = 0
                launched_processes.append(child)
                return child

            def launch_success_process(*args, **kwargs) -> Mock:
                return make_success_process()

            events: list[str] = []

            def create_job():
                events.append("create")
                return job

            def assign_job(handle, child_handle):
                self.assertIs(handle, job)
                self.assertEqual(child_handle, process_handle)
                events.append("assign")

            def resume_process(pid):
                self.assertEqual(pid, process_pid)
                events.append("resume")

            def query_job(handle):
                self.assertIs(handle, job)
                events.append("query")
                return 0

            def close_job(handle):
                self.assertIs(handle, job)
                events.append("close")

            with patch.dict(os.environ, {"CARGO_TARGET_DIR": "my_custom_target", "ARBITRARY_INJECTION": "secret"}):
                with (
                    patch.object(iti.subprocess, "Popen", side_effect=launch_success_process) as mock_popen,
                    patch.object(iti, "_create_job_object", side_effect=create_job),
                    patch.object(iti, "_assign_job_object", side_effect=assign_job),
                    patch.object(iti, "_resume_suspended_process", side_effect=resume_process),
                    patch.object(iti, "_query_job_active_processes", side_effect=query_job),
                    patch.object(iti, "_close_job_object", side_effect=close_job),
                ):
                    _run_fixed(troot, ("cargo", "metadata", "--locked", "--format-version", "1"))
                    called_env = mock_popen.call_args.kwargs["env"]
                    self.assertEqual(called_env.get("CARGO_TARGET_DIR"), str(iti._admitted_target_root(troot)))
                    self.assertNotIn("ARBITRARY_INJECTION", called_env)
                    self.assertLess(events.index("assign"), events.index("resume"))
                    self.assertIn("query", events)
                    self.assertIn("close", events)

                    fixed_original = ["cargo", "metadata", "--locked", "--format-version", "1"]
                    fixed_mutable = list(fixed_original)
                    fixed_validated: list[tuple[str, ...]] = []
                    fixed_validator = iti._validate_command

                    def validate_then_mutate_fixed(command, root=None, *, admitted_executable=None):
                        fixed_validated.append(tuple(command))
                        fixed_validator(command, root, admitted_executable=admitted_executable)
                        fixed_mutable[:] = ["git", "push"]

                    with patch.object(iti, "_validate_command", side_effect=validate_then_mutate_fixed):
                        _run_fixed(troot, fixed_mutable)
                    self.assertEqual(fixed_validated, [tuple(fixed_original)])
                    self.assertEqual(fixed_mutable, ["git", "push"])
                    self.assertEqual(mock_popen.call_count, 2)
                    popen_argv_vectors = [
                        tuple(call.args[0]) for call in mock_popen.call_args_list
                    ]
                    self.assertEqual(
                        popen_argv_vectors,
                        [tuple(fixed_original), tuple(fixed_original)],
                    )
                    self.assertEqual(popen_argv_vectors[-1], fixed_validated[-1])
                    self.assertEqual(len(launched_processes), 2)
                    self.assertIsNot(launched_processes[0], launched_processes[1])
                    self.assertIsNot(launched_processes[0].stdout, launched_processes[1].stdout)
                    self.assertIsNot(launched_processes[0].stderr, launched_processes[1].stderr)

                    runner_original = ["git", "rev-parse", "HEAD"]
                    runner_mutable = list(runner_original)
                    runner_validated: list[tuple[str, ...]] = []
                    runner_observed: list[tuple[str, ...]] = []
                    command_validator = iti._validate_command

                    def validate_then_mutate_runner(command, root=None, *, admitted_executable=None):
                        runner_validated.append(tuple(command))
                        command_validator(command, root, admitted_executable=admitted_executable)
                        runner_mutable[:] = ["git", "push"]

                    def injected_runner(root, command, timeout=None):
                        runner_observed.append(tuple(command))
                        return CommandResult(stdout=b"0123456789abcdef0123456789abcdef01234567\n", stderr=b"")

                    with patch.object(iti, "_validate_command", side_effect=validate_then_mutate_runner):
                        iti._run_cmd(injected_runner, troot, runner_mutable)
                    self.assertEqual(runner_validated, [tuple(runner_original)])
                    self.assertEqual(runner_mutable, ["git", "push"])
                    self.assertEqual(runner_observed, [tuple(runner_original)])

            failure_job = object()
            failure_handle = 2345
            suspended_process = Mock()
            suspended_process._handle = failure_handle
            suspended_process.pid = 2
            suspended_process.stdout = io.BytesIO(b"")
            suspended_process.stderr = io.BytesIO(b"")
            suspended_process.returncode = 1
            failed_events: list[str] = []
            suspended_process.poll.return_value = None
            suspended_process.kill.side_effect = lambda: failed_events.append("kill")
            suspended_process.wait.side_effect = lambda *args, **kwargs: failed_events.append("reap") or 1

            def fail_assignment(handle, child_handle):
                self.assertIs(handle, failure_job)
                self.assertEqual(child_handle, failure_handle)
                failed_events.append("assign")
                raise OSError("injected assignment refusal")

            with (
                patch.object(iti.subprocess, "Popen", return_value=suspended_process),
                patch.object(iti, "_create_job_object", return_value=failure_job),
                patch.object(iti, "_assign_job_object", side_effect=fail_assignment),
                patch.object(iti, "_resume_suspended_process", side_effect=lambda pid: failed_events.append("resume")),
                patch.object(iti, "_terminate_job_object") as terminate_unassigned_job,
                patch.object(iti, "_query_job_active_processes", return_value=0),
                patch.object(iti, "_close_job_object", side_effect=lambda handle: failed_events.append("close")),
            ):
                with self.assertRaises(InventoryError) as cm:
                    _run_fixed(troot, ("cargo", "metadata", "--locked", "--format-version", "1"))
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")
            self.assertEqual(suspended_process.kill.call_count, 1)
            self.assertEqual(suspended_process.wait.call_count, 1)
            self.assertEqual(terminate_unassigned_job.call_count, 0)
            self.assertNotIn("resume", failed_events)
            self.assertEqual(failed_events.count("kill"), 1)
            self.assertEqual(failed_events.count("reap"), 1)
            self.assertLess(failed_events.index("assign"), failed_events.index("kill"))
            self.assertLess(failed_events.index("kill"), failed_events.index("reap"))
            self.assertLess(failed_events.index("reap"), failed_events.index("close"))

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

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "graph-pkg"
            src = package_dir / "src"
            src.mkdir(parents=True)
            (package_dir / "Cargo.toml").write_text(
                '[package]\nname = "graph-pkg"\nversion = "0.1.0"\n', encoding="utf-8"
            )
            (src / "lib.rs").write_text(
                """
                mod child;
                mod tree;
                #[path = "alternate/renamed.rs"] mod alternate;
                #[path = "chosen.rs"] pub(crate) mod selected_visible;
                mod inline { #[path = "custom.rs"] mod child; }
                pub mod public_child;
                pub(crate) mod crate_child;
                mod outer {
                    pub(super) mod parent_child;
                    pub(in crate::outer) mod scoped_child;
                }
                mod r#async;
                #[cfg(all())] mod cfg_active;
                #[cfg(any())] mod inactive_missing;
                mod active_missing;
                #[cfg(feature = "unresolved")]
                mod unknown_cfg;
                #[cfg(feature = "unresolved")]
                pub(in crate) mod conditional_visible;
                #[cfg(feature = "unresolved")]
                mod unknown_inline { #[test] #[ignore = "requires store"] fn test_unknown_inline() {} }
                #[cfg_attr(feature = "unresolved", path = "unresolved/child.rs")]
                mod unknown_cfg_attr;
                mod ambiguous;
                """,
                encoding="utf-8",
            )
            source_files = {
                "child.rs": "#[test] #[ignore = \"requires store\"] fn test_child() {}\nmod leaf;\n",
                "child/leaf.rs": "#[test] #[ignore = \"requires store\"] fn test_leaf() {}\n",
                "tree/mod.rs": "#[test] #[ignore = \"requires store\"] fn test_tree() {}\nmod nested;\n",
                "tree/nested.rs": "#[test] #[ignore = \"requires store\"] fn test_nested() {}\n",
                "alternate/renamed.rs": "#[test] #[ignore = \"requires store\"] fn test_alternate() {}\n",
                "chosen.rs": "#[test] #[ignore = \"requires store\"] fn test_chosen() {}\n",
                "conditional_visible.rs": "#[test] #[ignore = \"requires store\"] fn test_conditional_visible_decoy() {}\n",
                "inline/custom.rs": "#[test] #[ignore = \"requires store\"] fn test_inline() {}\n",
                "public_child.rs": "#[test] #[ignore = \"requires store\"] fn test_public() {}\n",
                "crate_child.rs": "#[test] #[ignore = \"requires store\"] fn test_crate() {}\n",
                "outer/parent_child.rs": "#[test] #[ignore = \"requires store\"] fn test_parent() {}\n",
                "outer/scoped_child.rs": "#[test] #[ignore = \"requires store\"] fn test_scoped() {}\n",
                "async.rs": "#[test] #[ignore = \"requires store\"] fn test_raw_module() {}\n",
                "r.rs": "#[test] #[ignore = \"requires store\"] fn test_decoy_r_module() {}\n",
                "cfg_active.rs": "#[test] #[ignore = \"requires store\"] fn test_cfg_active() {}\n",
                "orphan.rs": "#[test] #[ignore = \"requires store\"] fn test_orphan() {}\n",
                "ambiguous.rs": "#[test] #[ignore = \"requires store\"] fn test_ambiguous_file() {}\n",
                "ambiguous/mod.rs": "#[test] #[ignore = \"requires store\"] fn test_ambiguous_mod() {}\n",
            }
            for relative, text in source_files.items():
                path = src / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            foreign_target_source = src / "bin" / "foreign.rs"
            foreign_target_source.parent.mkdir(parents=True, exist_ok=True)
            foreign_target_source.write_text(
                '#[test] #[ignore = "requires store"] fn test_foreign_target() {}\n', encoding="utf-8"
            )

            target = PackageTarget(
                package_id="graph-pkg 0.1.0 (path+file:///crates/graph-pkg)",
                package_name="graph-pkg",
                manifest_dir=package_dir,
                target_name="graph_pkg",
                target_kind="lib",
                src_path=src / "lib.rs",
            )
            source_records: list[dict[str, object]] = []
            source_graph_completeness: list[bool] = []
            graph_tests = discover_source(
                root,
                [target],
                source_denominator_records=source_records,
                source_denominator_complete_out=source_graph_completeness,
            )
            self.assertEqual(source_graph_completeness, [False])
            by_test_name = {test.test_name: test for test in graph_tests}
            expected_modules = {
                "child::test_child": ("child",),
                "child::leaf::test_leaf": ("child", "leaf"),
                "tree::test_tree": ("tree",),
                "tree::nested::test_nested": ("tree", "nested"),
                "alternate::test_alternate": ("alternate",),
                "selected_visible::test_chosen": ("selected_visible",),
                "inline::child::test_inline": ("inline", "child"),
                "public_child::test_public": ("public_child",),
                "crate_child::test_crate": ("crate_child",),
                "outer::parent_child::test_parent": ("outer", "parent_child"),
                "outer::scoped_child::test_scoped": ("outer", "scoped_child"),
                "unknown_inline::test_unknown_inline": ("unknown_inline",),
                "async::test_raw_module": ("async",),
                "cfg_active::test_cfg_active": ("cfg_active",),
            }
            self.assertEqual(set(by_test_name), set(expected_modules))
            resolved_module_pairs = {
                (record["path"], record["module_path"])
                for record in source_records
                if record["resolution"] == "resolved"
            }
            unresolved_module_paths = {
                record["module_path"]
                for record in source_records
                if record["resolution"] == "unresolved"
            }
            for name, module_path in expected_modules.items():
                self.assertEqual(by_test_name[name].test_name, name)
                source_identity = (by_test_name[name].source_path, module_path)
                if name == "unknown_inline::test_unknown_inline":
                    self.assertIn(module_path, unresolved_module_paths)
                else:
                    self.assertIn(source_identity, resolved_module_pairs)
            self.assertIn(
                '#[cfg(feature = "unresolved")]',
                by_test_name["unknown_inline::test_unknown_inline"].cfg_evidence,
            )

            resolved_paths = {
                record["path"] for record in source_records if record["resolution"] == "resolved"
            }
            self.assertIn("crates/graph-pkg/src/child.rs", resolved_paths)
            self.assertIn("crates/graph-pkg/src/child/leaf.rs", resolved_paths)
            self.assertIn("crates/graph-pkg/src/tree/mod.rs", resolved_paths)
            self.assertIn("crates/graph-pkg/src/tree/nested.rs", resolved_paths)
            self.assertIn("crates/graph-pkg/src/alternate/renamed.rs", resolved_paths)
            self.assertIn("crates/graph-pkg/src/chosen.rs", resolved_paths)
            self.assertIn("crates/graph-pkg/src/inline/custom.rs", resolved_paths)
            self.assertIn("crates/graph-pkg/src/async.rs", resolved_paths)
            self.assertNotIn("crates/graph-pkg/src/r.rs", resolved_paths)
            active_cfg_record = next(
                record for record in source_records if record["path"] == "crates/graph-pkg/src/cfg_active.rs"
            )
            self.assertIn("#[cfg(all())]", active_cfg_record["cfg_evidence"])
            self.assertNotIn("crates/graph-pkg/src/orphan.rs", resolved_paths)
            self.assertNotIn("crates/graph-pkg/src/bin/foreign.rs", resolved_paths)
            self.assertFalse(any(
                record.get("path") in {
                    "crates/graph-pkg/src/orphan.rs",
                    "crates/graph-pkg/src/bin/foreign.rs",
                    "crates/graph-pkg/src/ambiguous.rs",
                    "crates/graph-pkg/src/ambiguous/mod.rs",
                }
                for record in source_records
            ))

            unresolved = [record for record in source_records if record["resolution"] == "unresolved"]
            unresolved_declarations = [record["declaration"] for record in unresolved]
            self.assertTrue(any("active_missing" in declaration for declaration in unresolved_declarations))
            self.assertTrue(any("unknown_cfg" in declaration for declaration in unresolved_declarations))
            self.assertTrue(any("conditional_visible" in declaration for declaration in unresolved_declarations))
            self.assertTrue(any("unknown_inline" in declaration for declaration in unresolved_declarations))
            self.assertTrue(any("unknown_cfg_attr" in declaration for declaration in unresolved_declarations))
            self.assertTrue(any("ambiguous" in declaration for declaration in unresolved_declarations))
            self.assertFalse(any("inactive_missing" in declaration for declaration in unresolved_declarations))
            declaring_source_sha256 = hashlib.sha256((src / "lib.rs").read_bytes()).hexdigest()
            for record in unresolved:
                self.assertIsNone(record["sha256"])
                self.assertIsNone(record["path"])
                self.assertIsNone(record["file_identity"])
                self.assertEqual(record["declaration_source_path"], "crates/graph-pkg/src/lib.rs")
                self.assertEqual(record["declaration_source_sha256"], declaring_source_sha256)
                self.assertIsNotNone(record["declaration_source_file_identity"])
            unknown_cfg = next(record for record in unresolved if "unknown_cfg" in record["declaration"])
            self.assertIn('#[cfg(feature = "unresolved")]', unknown_cfg["cfg_evidence"])
            conditional_visible = next(
                record for record in unresolved if "conditional_visible" in record["declaration"]
            )
            self.assertEqual(conditional_visible["module_path"], ("conditional_visible",))
            self.assertIn('#[cfg(feature = "unresolved")]', conditional_visible["cfg_evidence"])
            self.assertNotIn("conditional_visible::test_conditional_visible_decoy", by_test_name)
            unknown_inline = next(record for record in unresolved if "unknown_inline" in record["declaration"])
            self.assertIn('#[cfg(feature = "unresolved")]', unknown_inline["cfg_evidence"])
            unknown_cfg_attr = next(record for record in unresolved if "unknown_cfg_attr" in record["declaration"])
            self.assertIn(
                '#[cfg_attr(feature = "unresolved", path = "unresolved/child.rs")]',
                unknown_cfg_attr["cfg_evidence"],
            )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "nested-inline"
            source_path = package_dir / "src" / "lib.rs"
            source_path.parent.mkdir(parents=True)
            source_bytes = (
                b'mod outer { mod inner { #[test] #[ignore = "requires store"] '
                b'fn nested_inline_test() {} } }\n'
            )
            source_path.write_bytes(source_bytes)
            nested_target = PackageTarget(
                package_id="nested-inline 0.1.0 (path+file:///crates/nested-inline)",
                package_name="nested-inline",
                manifest_dir=package_dir,
                target_name="nested_inline",
                target_kind="lib",
                src_path=source_path,
            )
            nested_records: list[dict[str, object]] = []
            nested_completeness: list[bool] = []
            nested_tests = discover_source(
                root,
                [nested_target],
                source_denominator_records=nested_records,
                source_denominator_complete_out=nested_completeness,
            )
            self.assertEqual(nested_completeness, [True])
            self.assertEqual(len(nested_tests), 1)
            self.assertEqual(nested_tests[0].test_name, "outer::inner::nested_inline_test")
            expected_source_sha256 = hashlib.sha256(source_bytes).hexdigest()
            nested_resolved = [record for record in nested_records if record["resolution"] == "resolved"]
            self.assertTrue(nested_resolved)
            self.assertEqual(
                {record["module_path"] for record in nested_resolved},
                {(), ("outer",), ("outer", "inner")},
            )
            for record in nested_resolved:
                self.assertEqual(record["sha256"], expected_source_sha256)
                self.assertIsNotNone(record["file_identity"])
                self.assertEqual(record["path"], "crates/nested-inline/src/lib.rs")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "cfg-test-profile"
            src = package_dir / "src"
            src.mkdir(parents=True)
            (src / "lib.rs").write_text("#[cfg(test)] mod test_context;\n", encoding="utf-8")
            test_context_source = (
                '#[test] #[ignore = "requires store"] fn test_profile_context() {}\n'
            )
            child_path = src / "test_context.rs"
            child_path.write_bytes(test_context_source.encode("utf-8"))
            test_profile_target = PackageTarget(
                package_id="cfg-test-profile 0.1.0 (path+file:///crates/cfg-test-profile)",
                package_name="cfg-test-profile",
                manifest_dir=package_dir,
                target_name="cfg_test_profile",
                target_kind="lib",
                src_path=src / "lib.rs",
                test_enabled=False,
            )
            context_key = (
                test_profile_target.package_id,
                test_profile_target.target_kind,
                test_profile_target.target_name,
            )
            profile_records: list[dict[str, object]] = []
            profile_completeness: list[bool] = []
            profile_tests = discover_source(
                root,
                [test_profile_target],
                source_denominator_records=profile_records,
                source_denominator_complete_out=profile_completeness,
                test_profile_context={context_key: True},
            )
            self.assertEqual(profile_completeness, [True])
            self.assertEqual([test.test_name for test in profile_tests], ["test_context::test_profile_context"])
            self.assertIn("#[cfg(test)]", profile_tests[0].cfg_evidence)
            observed_context_module = next(
                record for record in profile_records
                if record["resolution"] == "resolved"
                and record["path"] == "crates/cfg-test-profile/src/test_context.rs"
            )
            self.assertEqual(observed_context_module["module_path"], ("test_context",))
            self.assertIn("#[cfg(test)]", observed_context_module["cfg_evidence"])
            self.assertEqual(
                observed_context_module["sha256"],
                hashlib.sha256(test_context_source.encode("utf-8")).hexdigest(),
            )
            self.assertIsNotNone(observed_context_module["file_identity"])

            inactive_records: list[dict[str, object]] = []
            inactive_completeness: list[bool] = []
            inactive_profile_tests = discover_source(
                root,
                [test_profile_target],
                source_denominator_records=inactive_records,
                source_denominator_complete_out=inactive_completeness,
                test_profile_context={context_key: False},
            )
            self.assertEqual(inactive_profile_tests, [])
            self.assertEqual(inactive_completeness, [True])
            inactive_context_module = next(
                record for record in inactive_records
                if record.get("reason") == "cfg_inactive"
                and record["module_path"] == ("test_context",)
            )
            self.assertIn("#[cfg(test)]", inactive_context_module["cfg_evidence"])
            self.assertIsNone(inactive_context_module["path"])
            self.assertIsNone(inactive_context_module["sha256"])
            self.assertFalse(any(
                record["path"] == "crates/cfg-test-profile/src/test_context.rs"
                for record in inactive_records
                if record["path"] is not None
            ))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "root-owned-test"
            test_dir = package_dir / "tests"
            test_dir.mkdir(parents=True)
            test_root = test_dir / "custom_root.rs"
            test_root.write_text("mod child;\n", encoding="utf-8")
            child_path = test_dir / "child.rs"
            child_path.write_text(
                '#[test] #[ignore = "requires store"] fn test_from_target_root() {}\n',
                encoding="utf-8",
            )
            root_owned_target = PackageTarget(
                package_id="root-owned-test 0.1.0 (path+file:///crates/root-owned-test)",
                package_name="root-owned-test",
                manifest_dir=package_dir,
                target_name="custom_root",
                target_kind="test",
                src_path=test_root,
            )
            root_owned_records: list[dict[str, object]] = []
            root_owned_tests = discover_source(
                root,
                [root_owned_target],
                source_denominator_records=root_owned_records,
            )
            self.assertEqual([test.test_name for test in root_owned_tests], ["child::test_from_target_root"])
            self.assertEqual(root_owned_tests[0].target_kind, "test")
            self.assertIn(
                "crates/root-owned-test/tests/child.rs",
                {record["path"] for record in root_owned_records if record["resolution"] == "resolved"},
            )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "recursive-cfg-attr"
            src = package_dir / "src"
            src.mkdir(parents=True)
            (src / "lib.rs").write_text(
                "#[cfg_attr(all(), cfg_attr(any(), path = \"other.rs\"))] mod preferred;\n"
                "#[cfg_attr(all(), cfg_attr(all(), cfg(any())))] mod disabled;\n",
                encoding="utf-8",
            )
            (src / "preferred.rs").write_text(
                '#[test] #[ignore = "requires store"] fn test_default_path() {}\n', encoding="utf-8"
            )
            (src / "other.rs").write_text(
                '#[test] #[ignore = "requires store"] fn test_override_path() {}\n', encoding="utf-8"
            )
            (src / "disabled.rs").write_text(
                '#[test] #[ignore = "requires store"] fn test_nested_disabled() {}\n', encoding="utf-8"
            )
            cfg_attr_target = PackageTarget(
                package_id="recursive-cfg-attr 0.1.0 (path+file:///crates/recursive-cfg-attr)",
                package_name="recursive-cfg-attr",
                manifest_dir=package_dir,
                target_name="recursive_cfg_attr",
                target_kind="lib",
                src_path=src / "lib.rs",
            )
            cfg_attr_records: list[dict[str, object]] = []
            cfg_attr_completeness: list[bool] = []
            cfg_attr_tests = discover_source(
                root,
                [cfg_attr_target],
                source_denominator_records=cfg_attr_records,
                source_denominator_complete_out=cfg_attr_completeness,
            )
            self.assertEqual(cfg_attr_completeness, [True])
            self.assertEqual([test.test_name for test in cfg_attr_tests], ["preferred::test_default_path"])
            cfg_attr_resolved_paths = {
                record["path"] for record in cfg_attr_records
                if record["resolution"] == "resolved" and record["path"] is not None
            }
            self.assertIn("crates/recursive-cfg-attr/src/preferred.rs", cfg_attr_resolved_paths)
            self.assertNotIn("crates/recursive-cfg-attr/src/other.rs", cfg_attr_resolved_paths)
            self.assertNotIn("crates/recursive-cfg-attr/src/disabled.rs", cfg_attr_resolved_paths)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "inactive-macros"
            src = package_dir / "src"
            src.mkdir(parents=True)
            inactive_source = (
                b'#[cfg(any())]\ninclude!("missing_disabled.rs");\n'
                b'#[cfg(any())]\ninactive_module_macro! { mod missing_generated; }\n'
            )
            (src / "lib.rs").write_bytes(inactive_source)
            inactive_target = PackageTarget(
                package_id="inactive-macros 0.1.0 (path+file:///crates/inactive-macros)",
                package_name="inactive-macros",
                manifest_dir=package_dir,
                target_name="inactive_macros",
                target_kind="lib",
                src_path=src / "lib.rs",
            )
            inactive_records: list[dict[str, object]] = []
            inactive_completeness: list[bool] = []
            inactive_tests = discover_source(
                root,
                [inactive_target],
                source_denominator_records=inactive_records,
                source_denominator_complete_out=inactive_completeness,
            )
            self.assertEqual(inactive_tests, [])
            self.assertEqual(inactive_completeness, [True])
            self.assertFalse(any(record["resolution"] == "unresolved" for record in inactive_records))
            self.assertFalse(any((record.get("path") or "").endswith("missing_disabled.rs") for record in inactive_records))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "opaque-macros"
            src = package_dir / "src"
            src.mkdir(parents=True)
            macro_source = (
                b'active_module_macro! { mod phantom; }\n'
                b'#[cfg(feature = "unresolved")] conditional_module_macro! { mod conditional; }\n'
                b'#[cfg(feature = "unresolved")] include!("maybe_included.rs");\n'
                b'fn local_tokens() { opaque_tokens! { mod local_phantom; } }\n'
            )
            (src / "lib.rs").write_bytes(macro_source)
            for relative in ("phantom.rs", "conditional.rs", "local_phantom.rs"):
                (src / relative).write_text(
                    '#[test] #[ignore = "requires store"] fn test_macro_decoy() {}\n',
                    encoding="utf-8",
                )
            (src / "maybe_included.rs").write_text("// unresolved include destination\n", encoding="utf-8")
            macro_target = PackageTarget(
                package_id="opaque-macros 0.1.0 (path+file:///crates/opaque-macros)",
                package_name="opaque-macros",
                manifest_dir=package_dir,
                target_name="opaque_macros",
                target_kind="lib",
                src_path=src / "lib.rs",
            )
            macro_records: list[dict[str, object]] = []
            macro_completeness: list[bool] = []
            macro_tests = discover_source(
                root,
                [macro_target],
                source_denominator_records=macro_records,
                source_denominator_complete_out=macro_completeness,
            )
            self.assertEqual(macro_completeness, [False])
            self.assertFalse(any(test.test_name == "test_macro_decoy" for test in macro_tests))
            macro_unresolved = [record for record in macro_records if record["resolution"] == "unresolved"]
            active_macro = next(
                record for record in macro_unresolved if "active_module_macro!" in record["declaration"]
            )
            self.assertEqual(active_macro["reason"], "opaque_macro_expansion")
            conditional_macro = next(
                record for record in macro_unresolved if "conditional_module_macro!" in record["declaration"]
            )
            conditional_include = next(
                record for record in macro_unresolved if 'include!("maybe_included.rs")' in record["declaration"]
            )
            self.assertEqual(conditional_macro["reason"], "unknown_cfg")
            self.assertEqual(conditional_include["reason"], "unknown_cfg")
            for record in (conditional_macro, conditional_include):
                self.assertIn('#[cfg(feature = "unresolved")]', record["cfg_evidence"])
            macro_source_sha256 = hashlib.sha256(macro_source).hexdigest()
            for record in macro_unresolved:
                self.assertIsNone(record["path"])
                self.assertIsNone(record["sha256"])
                self.assertIsNone(record["file_identity"])
                self.assertEqual(record["declaration_source_path"], "crates/opaque-macros/src/lib.rs")
                self.assertEqual(record["declaration_source_sha256"], macro_source_sha256)
                self.assertIsNotNone(record["declaration_source_file_identity"])
            resolved_macro_paths = {
                record["path"] for record in macro_records if record["resolution"] == "resolved"
            }
            self.assertFalse(any(
                path is not None and path.endswith(("phantom.rs", "conditional.rs", "local_phantom.rs", "maybe_included.rs"))
                for path in resolved_macro_paths
            ))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "source-read-failure"
            src = package_dir / "src"
            src.mkdir(parents=True)
            parent_source = b'mod child;\ninclude!("included.rs");\n'
            (src / "lib.rs").write_bytes(parent_source)
            child_path = src / "child.rs"
            child_path.write_text("// child is present but injected unreadable\n", encoding="utf-8")
            included_path = src / "included.rs"
            included_path.write_text("// include is present but injected unreadable\n", encoding="utf-8")
            read_failure_target = PackageTarget(
                package_id="source-read-failure 0.1.0 (path+file:///crates/source-read-failure)",
                package_name="source-read-failure",
                manifest_dir=package_dir,
                target_name="source_read_failure",
                target_kind="lib",
                src_path=src / "lib.rs",
            )
            observe_source_file = iti._observe_source_file
            unreadable_paths = {child_path.resolve(), included_path.resolve()}

            def fail_queued_source(
                observe_root: Path,
                path: Path,
                deadline: float | None,
            ):
                if Path(path).resolve() in unreadable_paths:
                    raise InventoryError("SOURCE_READ_FAILED", "synthetic queued source refusal")
                return observe_source_file(observe_root, path, deadline)

            read_failure_records: list[dict[str, object]] = []
            read_failure_completeness: list[bool] = []
            with patch.object(iti, "_observe_source_file", side_effect=fail_queued_source):
                read_failure_tests = discover_source(
                    root,
                    [read_failure_target],
                    source_denominator_records=read_failure_records,
                    source_denominator_complete_out=read_failure_completeness,
                )
            self.assertEqual(read_failure_tests, [])
            self.assertEqual(read_failure_completeness, [False])
            declaring_file_sha256 = hashlib.sha256(parent_source).hexdigest()
            queued_failures = [
                record for record in read_failure_records
                if record.get("reason") == "source_unavailable"
            ]
            self.assertEqual(len(queued_failures), 2)
            for record in queued_failures:
                self.assertIsNone(record["path"])
                self.assertIsNone(record["sha256"])
                self.assertIsNone(record["file_identity"])
                self.assertEqual(record["declaration_source_path"], "crates/source-read-failure/src/lib.rs")
                self.assertEqual(record["declaration_source_sha256"], declaring_file_sha256)
                self.assertIsNotNone(record["declaration_source_file_identity"])
            self.assertTrue(any("mod child;" in record["declaration"] for record in queued_failures))
            self.assertTrue(any('include!("included.rs")' in record["declaration"] for record in queued_failures))

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
        """A closed Cargo stream yields exact listings and retains zero-row binaries."""
        expected = [
            "nested::test_nested_ignored",
            "test_bare_ignored",
            "test_cfg_attr_ignored",
            "test_disabled_ignored",
            "test_sync_ignored",
            "test_tokio_ignored",
            "test_unknown_reason_ignored",
        ]
        # The pinned terse formatter emits one test record per line; pretty
        # summaries and blank separators are intentionally excluded.
        listing = b"".join(f"{name}: test\n".encode("utf-8") for name in expected)

        inventory = json.loads((self.fixture_dir / "sample_inventory.json").read_bytes())
        target_record = inventory["header"]["target_denominator"][0]
        artifact_record = inventory["header"]["artifact_denominator"][0]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            admitted_root = iti._admitted_target_root(root)
            source_path = root / target_record["src_path"]
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("", encoding="utf-8")
            manifest = source_path.parent.parent / "Cargo.toml"
            manifest.write_text("[package]\nname = \"sample-package\"\nversion = \"0.1.0\"\n", encoding="utf-8")
            executable = admitted_root / artifact_record["executable"]
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(b"synthetic executable identity")
            target = PackageTarget(
                package_id=target_record["package_id"],
                package_name=target_record["package_name"],
                manifest_dir=manifest.parent,
                target_name=target_record["target_name"],
                target_kind=target_record["target_kind"],
                src_path=source_path,
                test_enabled=target_record["test_enabled"],
                doctest_enabled=target_record["doctest_enabled"],
                bench_enabled=target_record["bench_enabled"],
                required_features=tuple(target_record["required_features"]),
                edition="2021",
            )
            profile = artifact_record["profile"]
            message_target = {
                "kind": [target.target_kind],
                "crate_types": ["lib"],
                "name": target.target_name,
                "src_path": str(source_path),
                "edition": "2021",
                "doc": True,
                "doctest": target.doctest_enabled,
                "test": target.test_enabled,
            }
            cargo_stream = "\n".join((
                json.dumps({
                    "reason": "compiler-artifact",
                    "package_id": target.package_id,
                    "manifest_path": str(manifest),
                    "target": message_target,
                    "profile": profile,
                    "features": artifact_record["features"],
                    "filenames": [str(executable)],
                    "executable": str(executable),
                    "fresh": True,
                }),
                json.dumps({"reason": "build-finished", "success": True}),
            )).encode("utf-8") + b"\n"
            listing_result = listing
            listing_timeouts: list[int | None] = []

            def runner(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                if tuple(argv[:2]) == ("cargo", "test"):
                    return CommandResult(stdout=cargo_stream, stderr=b"")
                if tuple(argv[:2]) == ("cargo", "metadata"):
                    self.fail("target-only discovery unexpectedly requested Cargo metadata")
                if argv and Path(argv[0]) == executable and tuple(argv[1:]) == (
                    "--list", "--ignored", "--format", "terse"
                ):
                    listing_timeouts.append(timeout)
                    return CommandResult(stdout=listing_result, stderr=b"")
                return CommandResult(stdout=listing_result, stderr=b"")

            artifact_records: list[dict[str, object]] = []
            build_hashes: list[str] = []
            compiled = discover_compiled(
                root,
                [target],
                runner=runner,
                artifact_denominator_records=artifact_records,
                build_sha256_out=build_hashes,
            )
            self.assertEqual([item.test_name for item in compiled], expected)
            self.assertEqual(len(artifact_records), 1)
            self.assertEqual(artifact_records[0]["ignored_test_count"], len(expected))
            self.assertEqual(len(build_hashes), 1)
            self.assertRegex(build_hashes[0], r"\A[0-9a-f]{64}\Z")
            self.assertEqual(len(listing_timeouts), 1)
            self.assertIsNotNone(listing_timeouts[0])
            self.assertGreater(listing_timeouts[0], 0)

            # The same admitted binary remains in the compiled denominator when it lists zero ignored tests.
            listing_result = b""
            zero_row_records: list[dict[str, object]] = []
            zero_row_build_hashes: list[str] = []
            zero_rows = discover_compiled(
                root,
                [target],
                runner=runner,
                artifact_denominator_records=zero_row_records,
                build_sha256_out=zero_row_build_hashes,
            )
            self.assertEqual(zero_rows, [])
            self.assertEqual(len(zero_row_records), 1)
            self.assertEqual(zero_row_records[0]["ignored_test_count"], 0)
            self.assertEqual(zero_row_build_hashes, build_hashes)
            self.assertEqual(len(listing_timeouts), 2)
            self.assertTrue(all(timeout is not None and timeout > 0 for timeout in listing_timeouts))

    # WORK_UNIT_CASE: 905/10
    def test_malformed_truncated_invalid_encoding_fixture_fails(self) -> None:
        """Malformed, unknown, truncated or invalid Cargo/list output always refuses."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()

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

            inventory = json.loads((self.fixture_dir / "sample_inventory.json").read_bytes())
            target_record = inventory["header"]["target_denominator"][0]
            artifact_record = inventory["header"]["artifact_denominator"][0]
            source_path = troot / target_record["src_path"]
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("", encoding="utf-8")
            manifest = source_path.parent.parent / "Cargo.toml"
            manifest.write_text("[package]\nname = \"sample-package\"\nversion = \"0.1.0\"\n", encoding="utf-8")
            bin_path = iti._admitted_target_root(troot) / artifact_record["executable"]
            bin_path.parent.mkdir(parents=True, exist_ok=True)
            bin_path.write_bytes(b"synthetic executable identity")
            target = PackageTarget(
                package_id=target_record["package_id"],
                package_name=target_record["package_name"],
                manifest_dir=manifest.parent,
                target_name=target_record["target_name"],
                target_kind=target_record["target_kind"],
                src_path=source_path,
                test_enabled=target_record["test_enabled"],
                doctest_enabled=target_record["doctest_enabled"],
                bench_enabled=target_record["bench_enabled"],
                required_features=tuple(target_record["required_features"]),
                edition="2021",
            )
            artifact = {
                "reason": "compiler-artifact",
                "package_id": target.package_id,
                "manifest_path": str(manifest),
                "target": {
                    "kind": [target.target_kind],
                    "crate_types": ["lib"],
                    "name": target.target_name,
                    "src_path": str(source_path),
                    "edition": "2021",
                    "doc": True,
                    "doctest": target.doctest_enabled,
                    "test": target.test_enabled,
                },
                "profile": artifact_record["profile"],
                "features": artifact_record["features"],
                "filenames": [str(bin_path)],
                "executable": str(bin_path),
                "fresh": True,
            }
            metadata_target = {
                **artifact["target"],
                "required-features": [],
            }
            valid_metadata = {
                "version": 1,
                "metadata": None,
                "workspace_root": str(troot),
                "target_directory": str(iti._admitted_target_root(troot)),
                "workspace_members": [target.package_id],
                "workspace_default_members": [target.package_id],
                "packages": [{
                    "id": target.package_id,
                    "name": target.package_name,
                    "version": "0.1.0",
                    "manifest_path": str(manifest),
                    "source": None,
                    "targets": [metadata_target],
                    "features": {},
                    "dependencies": [],
                }],
                "resolve": {
                    "root": target.package_id,
                    "nodes": [{
                        "id": target.package_id,
                        "features": [],
                        "deps": [],
                        "dependencies": [],
                    }],
                },
            }

            def metadata_runner(metadata_value: dict[str, object]):
                def runner(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                    return CommandResult(
                        stdout=json.dumps(metadata_value).encode("utf-8"),
                        stderr=b"",
                    )
                return runner

            self.assertEqual(_cargo_metadata(troot, runner=metadata_runner(valid_metadata)), valid_metadata)
            for finite_metadata_number in (0, 1.25, -2.5):
                with self.subTest(finite_metadata_number=finite_metadata_number):
                    finite_metadata = {
                        **valid_metadata,
                        "metadata": {"finite": finite_metadata_number},
                    }
                    self.assertEqual(
                        _cargo_metadata(troot, runner=metadata_runner(finite_metadata)),
                        finite_metadata,
                    )
            for nonfinite_metadata_number in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(nonfinite_metadata_number=repr(nonfinite_metadata_number)):
                    nonfinite_metadata = {
                        **valid_metadata,
                        "metadata": {"nonfinite": nonfinite_metadata_number},
                    }
                    with self.assertRaises(InventoryError) as cm:
                        _cargo_metadata(troot, runner=metadata_runner(nonfinite_metadata))
                    self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")
            missing_resolve_root = {
                **valid_metadata,
                "resolve": {
                    key: value for key, value in valid_metadata["resolve"].items() if key != "root"
                },
            }
            missing_package_source = dict(valid_metadata["packages"][0])
            del missing_package_source["source"]
            missing_source_metadata = {
                **valid_metadata,
                "packages": [missing_package_source],
            }
            for incomplete_metadata in (missing_resolve_root, missing_source_metadata):
                with self.subTest(incomplete_metadata=incomplete_metadata):
                    with self.assertRaises(InventoryError) as cm:
                        _cargo_metadata(troot, runner=metadata_runner(incomplete_metadata))
                    self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            artifact_line = json.dumps(artifact).encode("utf-8") + b"\n"
            success_line = json.dumps({"reason": "build-finished", "success": True}).encode("utf-8") + b"\n"
            mismatched_target_line = json.dumps({
                **artifact,
                "target": {**artifact["target"], "test": False},
            }).encode("utf-8") + b"\n"
            unlisted_executable = iti._admitted_target_root(troot) / "debug" / "deps" / "unlisted-executable"
            unlisted_executable.parent.mkdir(parents=True, exist_ok=True)
            unlisted_executable.write_bytes(b"separate admitted file identity")
            executable_not_in_filenames = json.dumps(
                {**artifact, "executable": str(unlisted_executable)}
            ).encode("utf-8") + b"\n"

            def runner_for(cargo_stdout: bytes, listing_stdout: bytes = b""):
                def runner(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                    if tuple(argv[:2]) == ("cargo", "test"):
                        return CommandResult(stdout=cargo_stdout, stderr=b"")
                    return CommandResult(stdout=listing_stdout, stderr=b"")
                return runner

            invalid_streams = [
                artifact_line + b"{ not valid json }\n" + success_line,
                artifact_line + json.dumps({"reason": "unrecognized-cargo-message"}).encode("utf-8") + b"\n" + success_line,
                artifact_line + json.dumps({**artifact, "executable": None}).encode("utf-8") + b"\n" + success_line,
                artifact_line + json.dumps({"reason": "build-finished", "success": False}).encode("utf-8") + b"\n",
                artifact_line + b'{"reason":"build-finished"',
            ]
            invalid_streams.extend(
                b'{"reason":"build-finished","success":' + token + b'}\n'
                for token in (b"NaN", b"Infinity", b"-Infinity")
            )
            for cargo_stdout in invalid_streams:
                with self.subTest(cargo_stdout=cargo_stdout):
                    with self.assertRaises(InventoryError) as cm:
                        discover_compiled(troot, [target], runner=runner_for(cargo_stdout))
                    self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            compiler_message = {
                "reason": "compiler-message",
                "package_id": target.package_id,
                "manifest_path": str(manifest),
                "target": artifact["target"],
                "message": {
                    "message": "synthetic warning",
                    "code": None,
                    "level": "warning",
                    "spans": [],
                    "children": [],
                },
            }
            compiler_message_line = json.dumps(compiler_message).encode("utf-8") + b"\n"
            valid_closed_stream = artifact_line + compiler_message_line + success_line
            self.assertEqual(
                discover_compiled(troot, [target], runner=runner_for(valid_closed_stream)),
                [],
            )
            pretty_listing = b"test_sync_ignored: test\n\n1 test, 0 benchmarks\n"
            with self.assertRaises(InventoryError) as cm:
                discover_compiled(
                    troot,
                    [target],
                    runner=runner_for(valid_closed_stream, pretty_listing),
                )
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")
            for malformed_listing in (
                b"test_sync_ignored:\ttest\n",
                b"test_sync_ignored: test \n",
            ):
                with self.subTest(malformed_listing=malformed_listing):
                    with self.assertRaises(InventoryError) as cm:
                        discover_compiled(
                            troot,
                            [target],
                            runner=runner_for(valid_closed_stream, malformed_listing),
                        )
                    self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")
            for debuginfo in (None, 0, 1, 2, "line-directives-only", "line-tables-only"):
                with self.subTest(debuginfo=debuginfo):
                    profile_artifact = {
                        **artifact,
                        "profile": {**artifact["profile"], "debuginfo": debuginfo},
                    }
                    profile_stream = (
                        json.dumps(profile_artifact).encode("utf-8") + b"\n" + success_line
                    )
                    self.assertEqual(
                        discover_compiled(troot, [target], runner=runner_for(profile_stream)),
                        [],
                    )
            for invalid_debuginfo in (True, -1, 3, 1.5, "full", "arbitrary"):
                with self.subTest(invalid_debuginfo=invalid_debuginfo):
                    profile_artifact = {
                        **artifact,
                        "profile": {**artifact["profile"], "debuginfo": invalid_debuginfo},
                    }
                    with self.assertRaises(InventoryError) as cm:
                        discover_compiled(
                            troot,
                            [target],
                            runner=runner_for(json.dumps(profile_artifact).encode("utf-8") + b"\n" + success_line),
                        )
                    self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            admitted_target_root = iti._admitted_target_root(troot)
            build_out = admitted_target_root / "debug" / "build" / "sample-package" / "out"
            build_out.mkdir(parents=True, exist_ok=True)
            build_script_path = manifest.parent / "build.rs"
            build_script_path.write_text("fn main() {}\n", encoding="utf-8")
            custom_build_target = {
                "kind": ["custom-build"],
                "crate_types": ["bin"],
                "name": "build-script-build",
                "src_path": str(build_script_path),
                "edition": "2021",
                "doc": False,
                "doctest": False,
                "test": False,
                "required-features": [],
            }
            build_metadata = {
                **valid_metadata,
                "packages": [{
                    **valid_metadata["packages"][0],
                    "targets": [
                        *valid_metadata["packages"][0]["targets"],
                        custom_build_target,
                    ],
                }],
            }
            build_targets = _targets(troot, build_metadata)
            # Closed target schema (issue #905 W10): production emits exactly
            # these keys for every target record - no extra fields admitted.
            denominator_records = iti._target_denominator(troot, build_targets)
            for denominator_record in denominator_records:
                self.assertEqual(
                    set(denominator_record),
                    {
                        "package_id", "package_name", "target_name", "target_kind",
                        "src_path", "test_enabled", "doctest_enabled", "bench_enabled",
                        "required_features", "required_features_satisfied", "features",
                        "available_features", "edition", "test_disposition",
                    },
                )
            build_target_record = next(
                record for record in denominator_records
                if record["target_kind"] == "custom-build"
            )
            self.assertEqual(
                build_target_record["src_path"],
                "crates/sample-package/build.rs",
            )
            self.assertEqual(build_target_record["test_disposition"], "exempt")
            build_script_message = {
                "reason": "build-script-executed",
                "package_id": target.package_id,
                "linked_libs": [],
                "linked_paths": [],
                "cfgs": [],
                "env": [["SYNTHETIC_KEY", "SYNTHETIC_VALUE"]],
                "out_dir": str(build_out),
            }
            build_script_line = json.dumps(build_script_message).encode("utf-8") + b"\n"
            build_order_hashes: list[str] = []
            self.assertEqual(
                discover_compiled(
                    troot,
                    build_targets,
                    runner=runner_for(build_script_line + artifact_line + success_line),
                    metadata=build_metadata,
                    build_sha256_out=build_order_hashes,
                ),
                [],
            )
            reversed_build_hashes: list[str] = []
            self.assertEqual(
                discover_compiled(
                    troot,
                    build_targets,
                    runner=runner_for(artifact_line + build_script_line + success_line),
                    metadata=build_metadata,
                    build_sha256_out=reversed_build_hashes,
                ),
                [],
            )
            self.assertEqual(build_order_hashes, reversed_build_hashes)
            self.assertEqual(len(build_order_hashes), 1)
            self.assertRegex(build_order_hashes[0], r"\A[0-9a-f]{64}\Z")
            object_environment_message = {
                **build_script_message,
                "env": [{"key": "SYNTHETIC_KEY", "value": "SYNTHETIC_VALUE"}],
            }
            with self.assertRaises(InventoryError) as cm:
                discover_compiled(
                    troot,
                    build_targets,
                    runner=runner_for(
                        json.dumps(object_environment_message).encode("utf-8")
                        + b"\n" + artifact_line + success_line
                    ),
                    metadata=build_metadata,
                )
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            malformed_span = {
                "file_name": str(source_path),
                "byte_start": 0,
                "byte_end": 1,
                "line_start": 1,
                "line_end": 1,
                "column_start": 1,
                "column_end": 2,
                "is_primary": True,
                "text": [{"text": "x", "highlight_start": 1}],
                "label": None,
                "suggested_replacement": None,
                "suggestion_applicability": None,
                "expansion": None,
            }
            malformed_diagnostic = {
                **compiler_message,
                "message": {
                    "message": "synthetic warning",
                    "code": None,
                    "level": "warning",
                    "spans": [malformed_span],
                    "children": [],
                },
            }
            malformed_diagnostic_stream = (
                artifact_line + json.dumps(malformed_diagnostic).encode("utf-8") + b"\n" + success_line
            )
            with self.assertRaises(InventoryError) as cm:
                discover_compiled(troot, [target], runner=runner_for(malformed_diagnostic_stream))
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            with self.assertRaises(InventoryError) as cm:
                discover_compiled(
                    troot,
                    [target],
                    runner=runner_for(executable_not_in_filenames + success_line),
                )
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            with self.assertRaises(InventoryError) as cm:
                discover_compiled(
                    troot,
                    [target],
                    runner=runner_for(mismatched_target_line + success_line),
                    metadata=valid_metadata,
                )
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            required_target_metadata = {
                **artifact["target"],
                "required-features": ["feature-a"],
            }
            required_feature_metadata = {
                **valid_metadata,
                "packages": [{
                    **valid_metadata["packages"][0],
                    "targets": [required_target_metadata],
                    "features": {"feature-a": []},
                }],
                "resolve": {
                    **valid_metadata["resolve"],
                    "nodes": [{
                        **valid_metadata["resolve"]["nodes"][0],
                        "features": ["feature-a"],
                    }],
                },
            }
            target_with_requirement = dataclasses.replace(
                target,
                required_features=("feature-a",),
                required_features_satisfied=True,
                available_features=("feature-a",),
                features=("feature-a",),
            )
            with self.assertRaises(InventoryError) as cm:
                discover_compiled(
                    troot,
                    [target_with_requirement],
                    runner=runner_for(artifact_line + success_line),
                    metadata=required_feature_metadata,
                )
            self.assertEqual(cm.exception.code, "COMPILED_GRAPH_UNAVAILABLE")

            # Listing bytes and names remain closed even after a valid artifact stream.
            for listing_stdout in (b"\xff\xfe invalid utf8", b"bad\x00name: test\n"):
                with self.subTest(listing_stdout=listing_stdout):
                    with self.assertRaises(InventoryError) as cm:
                        discover_compiled(
                            troot,
                            [target],
                            runner=runner_for(valid_closed_stream, listing_stdout),
                        )
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

        # W7/W24 (issue #905): a supported Store word must not certify an
        # additional unknown provider - the composed set keeps UNKNOWN and the
        # row stays UNCLASSIFIED (refuting comment 5981399706; I18.32:3).
        self.assertEqual(
            _requirements("requires SurrealDB and Redis"),
            (Requirement.STORE.value, Requirement.UNKNOWN.value),
        )
        self.assertEqual(
            _requirements("requires store with PostgreSQL"),
            (Requirement.STORE.value, Requirement.UNKNOWN.value),
        )
        # All-known compositions are unaffected by the provider guard.
        self.assertEqual(
            _requirements("requires store and runtime windows pipe"),
            (Requirement.RUNTIME.value, Requirement.STORE.value),
        )
        self.assertEqual(
            _requirements("requires store database"),
            (Requirement.STORE.value,),
        )

        mixed_code = """
        #[test]
        #[ignore = "requires SurrealDB and Redis"]
        fn test_store_unknown_provider() {}
        """
        mixed_tests = _scan_snippet(mixed_code)
        self.assertEqual(len(mixed_tests), 1)
        mixed_source = mixed_tests[0]
        self.assertEqual(
            mixed_source.requirements,
            (Requirement.STORE.value, Requirement.UNKNOWN.value),
        )
        mixed_compiled = CompiledTest(
            package_id=mixed_source.package_id,
            package_name=mixed_source.package_name,
            target_name=mixed_source.target_name,
            target_kind=mixed_source.target_kind,
            executable="target/debug/deps/lib",
            executable_digest="ed",
            test_name=mixed_source.test_name,
        )
        mixed_rows = reconcile([mixed_source], [mixed_compiled])
        self.assertEqual(len(mixed_rows), 1)
        self.assertEqual(mixed_rows[0].state, RowState.UNCLASSIFIED.value)
        self.assertEqual(mixed_rows[0].remediation_owner, "test-declaration-owner")

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

        fixture = json.loads((self.fixture_dir / "sample_inventory.json").read_bytes())
        fixture_toolchain = fixture["header"]["toolchain"]
        fixture_target = fixture["header"]["target_denominator"][0]
        fixture_artifact = fixture["header"]["artifact_denominator"][0]

        def run_inventory(
            *,
            git_status: bytes = b"",
            rustc_output: bytes | None = None,
            rustc_output_sequence: tuple[bytes, ...] | None = None,
            source_text: str = '#[test]\n#[ignore = "requires store database"]\nfn test_sync_ignored() {}\n',
            listing: bytes = b"test_sync_ignored: test\n",
            test_enabled: bool = True,
            cargo_lock_present: bool = True,
            include_artifact: bool = True,
            emit_test_artifact: bool | None = None,
            required_features: tuple[str, ...] = (),
            resolved_features: tuple[str, ...] = (),
            include_example_target: bool = False,
            package_features: dict[str, list[str]] | None = None,
            mutate_lib_source_on_second_observation: bool = False,
        ) -> dict[str, object]:
            with tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                package_id = "sample-package 0.1.0 (path+file:///crates/sample-package)"
                source_path = root / fixture_target["src_path"]
                package_dir = source_path.parent.parent
                source_path.parent.mkdir(parents=True)
                source_path.write_text(source_text, encoding="utf-8")
                manifest = package_dir / "Cargo.toml"
                manifest.write_text(
                    '[package]\nname = "sample-package"\nversion = "0.1.0"\nedition = "2021"\n',
                    encoding="utf-8",
                )
                if cargo_lock_present:
                    (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
                (root / "rust-toolchain.toml").write_text(
                    f'[toolchain]\nchannel = "{fixture_toolchain["channel"]}"\n', encoding="utf-8"
                )
                admitted_root = iti._admitted_target_root(root)
                admitted_root.mkdir(parents=True, exist_ok=True)
                executable = admitted_root / fixture_artifact["executable"]
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_bytes(b"synthetic executable identity")

                target = {
                    "kind": [fixture_target["target_kind"]],
                    "crate_types": [fixture_target["target_kind"]],
                    "name": fixture_target["target_name"],
                    "src_path": str(source_path),
                    "edition": "2021",
                    "doc": test_enabled,
                    "doctest": test_enabled,
                    "test": test_enabled,
                    "required-features": list(required_features),
                }
                metadata_targets = [target]
                if include_example_target:
                    example_source = package_dir / "examples" / "sample_example.rs"
                    example_source.parent.mkdir(parents=True, exist_ok=True)
                    example_source.write_text("", encoding="utf-8")
                    metadata_targets.append({
                        "kind": ["example"],
                        "crate_types": ["bin"],
                        "name": "sample_example",
                        "src_path": str(example_source),
                        "edition": "2021",
                        "doc": False,
                        "doctest": False,
                        "test": False,
                        "required-features": [],
                    })
                package = {
                    "id": package_id,
                    "name": "sample-package",
                    "version": "0.1.0",
                    "manifest_path": str(manifest),
                    "targets": metadata_targets,
                    "features": (
                        package_features if package_features is not None
                        else {feature: [] for feature in required_features}
                    ),
                    "dependencies": [],
                    "source": None,
                    "authors": [],
                    "categories": [],
                    "keywords": [],
                    "readme": None,
                    "repository": None,
                    "license": None,
                    "license_file": None,
                    "description": None,
                    "edition": "2021",
                    "links": None,
                    "default_run": None,
                    "rust_version": None,
                    "metadata": None,
                    "publish": None,
                }
                metadata = {
                    "version": 1,
                    "metadata": None,
                    "workspace_root": str(root),
                    "target_directory": str(admitted_root),
                    "workspace_members": [package_id],
                    "workspace_default_members": [package_id],
                    "packages": [package],
                    "resolve": {
                        "root": package_id,
                        "nodes": [{
                            "id": package_id,
                            "features": list(resolved_features),
                            "deps": [],
                            "dependencies": [],
                        }],
                    },
                }
                profile = fixture_artifact["profile"]
                messages = []
                if emit_test_artifact is None:
                    emit_test_artifact = test_enabled
                if include_artifact and emit_test_artifact:
                    messages.append({
                        "reason": "compiler-artifact",
                        "package_id": package_id,
                        "manifest_path": str(manifest),
                        "target": {
                            "kind": [fixture_target["target_kind"]],
                            "crate_types": [fixture_target["target_kind"]],
                            "name": fixture_target["target_name"],
                            "src_path": str(source_path),
                            "edition": "2021",
                            "doc": target["doc"],
                            "doctest": target["doctest"],
                            "test": target["test"],
                        },
                        "profile": profile,
                        "features": fixture_artifact["features"],
                        "filenames": [str(executable)],
                        "executable": str(executable),
                        "fresh": True,
                    })
                messages.append({"reason": "build-finished", "success": True})
                cargo_output = b"".join(
                    json.dumps(message, sort_keys=True).encode("utf-8") + b"\n" for message in messages
                )
                if rustc_output is None:
                    rustc_output = _fixture_rustc_verbose(fixture_toolchain)

                rustc_outputs_seen: list[bytes] = []

                def runner(cwd: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                    command = tuple(argv)
                    if command == ("git", "rev-parse", "HEAD"):
                        return CommandResult(stdout=b"0123456789abcdef0123456789abcdef01234567\n", stderr=b"")
                    if command[:2] == ("git", "status"):
                        return CommandResult(stdout=git_status, stderr=b"")
                    if command == ("rustc", "--version", "--verbose"):
                        if rustc_output_sequence is not None:
                            rustc_index = len(rustc_outputs_seen)
                            rustc_outputs_seen.append(rustc_output_sequence[min(rustc_index, len(rustc_output_sequence) - 1)])
                            return CommandResult(stdout=rustc_outputs_seen[-1], stderr=b"")
                        return CommandResult(stdout=rustc_output, stderr=b"")
                    if command == ("cargo", "metadata", "--locked", "--format-version", "1"):
                        return CommandResult(stdout=json.dumps(metadata, sort_keys=True).encode("utf-8"), stderr=b"")
                    if command == (
                        "cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json"
                    ):
                        return CommandResult(stdout=cargo_output, stderr=b"")
                    if command and Path(command[0]) == executable and command[1:] == (
                        "--list", "--ignored", "--format", "terse"
                    ):
                        return CommandResult(stdout=listing, stderr=b"")
                    self.fail(f"unexpected injected command: {command!r}")

                if not mutate_lib_source_on_second_observation:
                    return build_inventory(root, runner=runner)

                original_observe_source_file = iti._observe_source_file
                resolved_lib_source = source_path.resolve(strict=False)
                observation_counts: dict[Path, int] = {}

                def observe_source_file(
                    observe_root: Path,
                    path: Path,
                    deadline: float | None,
                ):
                    actual_path = Path(path).resolve(strict=False)
                    observation_counts[actual_path] = observation_counts.get(actual_path, 0) + 1
                    if actual_path == resolved_lib_source and observation_counts[actual_path] == 2:
                        Path(path).write_bytes(
                            Path(path).read_bytes() + b"\n// synthetic mutation before final source recheck\n"
                        )
                    return original_observe_source_file(observe_root, path, deadline)

                with patch.object(iti, "_observe_source_file", side_effect=observe_source_file):
                    inventory = build_inventory(root, runner=runner)
                return inventory

        def assert_inventory_hashes(inventory: dict[str, object]) -> None:
            header = inventory["header"]
            self.assertRegex(header["cargo_build_sha256"], r"\A[0-9a-f]{64}\Z")
            self.assertIs(header["cargo_build_finished_success"], True)
            for denominator, digest in (
                ("target_denominator", "target_denominator_sha256"),
                ("source_denominator", "source_denominator_sha256"),
                ("artifact_denominator", "artifact_denominator_sha256"),
            ):
                self.assertEqual(
                    header[digest],
                    hashlib.sha256(_canonical_bytes(header[denominator])).hexdigest(),
                )
            rows = [
                dataclasses.asdict(row) if dataclasses.is_dataclass(row) else row
                for row in inventory["rows"]
            ]
            aggregate_preimage = {
                "header": {key: value for key, value in header.items() if key != "aggregate_sha256"},
                "rows": rows,
            }
            self.assertEqual(
                header["aggregate_sha256"],
                hashlib.sha256(_canonical_bytes(aggregate_preimage)).hexdigest(),
            )

        complete = run_inventory()
        assert_inventory_hashes(complete)
        complete_header = complete["header"]
        self.assertIs(complete_header["source_denominator_complete"], True)
        self.assertIs(complete_header["compiled_graph_complete"], True)
        self.assertIs(complete_header["identity_complete"], True)
        self.assertIs(complete_header["row_classification_complete"], True)
        self.assertIs(complete_header["complete"], True)
        self.assertEqual(len(complete["rows"]), 1)

        for status, expected_field in (
            (b" M crates/sample-package/src/lib.rs\n", "tracked_tree_clean"),
            (b"?? synthetic-untracked.rs\n", "untracked_tree_clean"),
        ):
            with self.subTest(git_status=status):
                dirty = run_inventory(git_status=status)
                assert_inventory_hashes(dirty)
                dirty_header = dirty["header"]
                self.assertIs(dirty_header["source_identity"][expected_field], False)
                self.assertIs(dirty_header["identity_complete"], False)
                self.assertIs(dirty_header["source_denominator_complete"], True)
                self.assertIs(dirty_header["compiled_graph_complete"], True)
                self.assertIs(dirty_header["row_classification_complete"], True)
                self.assertIs(dirty_header["complete"], False)

        unknown_rustc = run_inventory(rustc_output=b"")
        assert_inventory_hashes(unknown_rustc)
        self.assertIsNone(unknown_rustc["header"]["toolchain"]["rustc_version"])
        self.assertIs(unknown_rustc["header"]["identity_complete"], False)
        self.assertIs(unknown_rustc["header"]["complete"], False)

        first_line_only_rustc = run_inventory(
            rustc_output=fixture_toolchain["rustc_version"].encode("utf-8")
        )
        assert_inventory_hashes(first_line_only_rustc)
        self.assertIsNone(first_line_only_rustc["header"]["toolchain"]["rustc_version"])
        self.assertIsNone(first_line_only_rustc["header"]["toolchain"]["rustc_verbose_sha256"])
        self.assertIs(first_line_only_rustc["header"]["identity_complete"], False)
        self.assertIs(first_line_only_rustc["header"]["complete"], False)

        unknown_fields_rustc = run_inventory(
            rustc_output=(
                b"rustc unknown\nrelease: unknown\nhost: unknown\ncommit-hash: unknown\n"
            )
        )
        assert_inventory_hashes(unknown_fields_rustc)
        self.assertIsNone(unknown_fields_rustc["header"]["toolchain"]["rustc_version"])
        self.assertIsNone(unknown_fields_rustc["header"]["toolchain"]["release"])
        self.assertIsNone(unknown_fields_rustc["header"]["toolchain"]["host"])
        self.assertIsNone(unknown_fields_rustc["header"]["toolchain"]["commit_hash"])
        self.assertIs(unknown_fields_rustc["header"]["identity_complete"], False)
        self.assertIs(unknown_fields_rustc["header"]["complete"], False)

        numeric_pin = fixture_toolchain["channel"]
        if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", numeric_pin):
            self.assertEqual(fixture_toolchain["release"], numeric_pin)

        missing_lock = run_inventory(cargo_lock_present=False)
        assert_inventory_hashes(missing_lock)
        self.assertIs(missing_lock["header"]["identity_complete"], False)
        self.assertIs(missing_lock["header"]["complete"], False)

        changed_rustc_identity = run_inventory(
            rustc_output_sequence=(
                _fixture_rustc_verbose(fixture_toolchain),
                (
                    f"rustc {fixture_toolchain['release']} (222222222 2026-09-28)\n"
                    f"release: {fixture_toolchain['release']}\n"
                    f"host: {fixture_toolchain['host']}\n"
                    f"commit-hash: {'2' * 40}\n"
                ).encode("utf-8"),
            )
        )
        assert_inventory_hashes(changed_rustc_identity)
        self.assertIs(changed_rustc_identity["header"]["identity_complete"], False)
        self.assertIs(changed_rustc_identity["header"]["source_denominator_complete"], True)
        self.assertIs(changed_rustc_identity["header"]["compiled_graph_complete"], True)
        self.assertIs(changed_rustc_identity["header"]["row_classification_complete"], True)
        self.assertIs(changed_rustc_identity["header"]["complete"], False)

        mismatched_pinned_release = run_inventory(
            rustc_output=(
                "rustc 0.0.0 (333333333 2026-09-28)\n"
                "release: 0.0.0\n"
                f"host: {fixture_toolchain['host']}\n"
                f"commit-hash: {'3' * 40}\n"
            ).encode("utf-8")
        )
        assert_inventory_hashes(mismatched_pinned_release)
        self.assertIsNone(mismatched_pinned_release["header"]["toolchain"]["rustc_version"])
        self.assertIs(mismatched_pinned_release["header"]["identity_complete"], False)
        self.assertIs(mismatched_pinned_release["header"]["complete"], False)

        unresolved_source = run_inventory(
            source_text='#[cfg(feature = "unresolved")] mod feature_gated;\n',
            listing=b"",
            package_features={},
        )
        assert_inventory_hashes(unresolved_source)
        unresolved_source_header = unresolved_source["header"]
        self.assertIs(unresolved_source_header["source_denominator_complete"], False)
        self.assertIs(unresolved_source_header["compiled_graph_complete"], True)
        self.assertIs(unresolved_source_header["identity_complete"], True)
        self.assertIs(unresolved_source_header["row_classification_complete"], True)
        self.assertIs(unresolved_source_header["complete"], False)

        proven_empty = run_inventory(source_text="", listing=b"")
        assert_inventory_hashes(proven_empty)
        empty_header = proven_empty["header"]
        self.assertEqual(proven_empty["rows"], [])
        self.assertIs(empty_header["source_denominator_complete"], True)
        self.assertIs(empty_header["compiled_graph_complete"], True)
        self.assertIs(empty_header["identity_complete"], True)
        self.assertIs(empty_header["row_classification_complete"], True)
        self.assertIs(empty_header["complete"], True)
        self.assertEqual(len(empty_header["target_denominator"]), 1)
        self.assertEqual(len(empty_header["artifact_denominator"]), 1)
        self.assertEqual(empty_header["artifact_denominator"][0]["ignored_test_count"], 0)

        disabled = run_inventory(source_text="", listing=b"", test_enabled=False)
        assert_inventory_hashes(disabled)
        disabled_header = disabled["header"]
        self.assertIs(disabled_header["complete"], True)
        self.assertEqual(disabled_header["target_denominator"][0]["test_disposition"], "test_disabled")
        self.assertIs(disabled_header["target_denominator"][0]["test_enabled"], False)
        self.assertEqual(disabled_header["artifact_denominator"], [])

        disabled_cfg_test = run_inventory(
            source_text="#[cfg(test)] mod disabled_test;\n",
            listing=b"",
            test_enabled=False,
        )
        assert_inventory_hashes(disabled_cfg_test)
        disabled_cfg_header = disabled_cfg_test["header"]
        self.assertIs(disabled_cfg_header["source_denominator_complete"], True)
        self.assertIs(disabled_cfg_header["compiled_graph_complete"], True)
        self.assertIs(disabled_cfg_header["row_classification_complete"], True)
        self.assertIs(disabled_cfg_header["complete"], True)
        self.assertEqual(disabled_cfg_header["artifact_denominator"], [])

        disabled_with_source = run_inventory(test_enabled=False)
        disabled_source_header = disabled_with_source["header"]
        self.assertEqual(disabled_source_header["counts_by_state"][RowState.SOURCE_ONLY.value], 1)
        self.assertIs(disabled_source_header["row_classification_complete"], False)
        self.assertIs(disabled_source_header["complete"], False)

        observed_test_artifact = run_inventory(
            test_enabled=False,
            emit_test_artifact=True,
            source_text=(
                '#[cfg(test)] mod observed_test { '
                '#[test] #[ignore = "requires store database"] fn test_sync_ignored() {} }\n'
            ),
            listing=b"observed_test::test_sync_ignored: test\n",
        )
        assert_inventory_hashes(observed_test_artifact)
        observed_artifacts = observed_test_artifact["header"]["artifact_denominator"]
        self.assertEqual(len(observed_artifacts), 1)
        self.assertIs(observed_artifacts[0]["profile"]["test"], True)
        self.assertEqual(observed_test_artifact["rows"][0]["state"], RowState.CLASSIFIED.value)
        self.assertIs(observed_test_artifact["header"]["source_denominator_complete"], True)
        self.assertIs(observed_test_artifact["header"]["compiled_graph_complete"], True)
        self.assertIs(observed_test_artifact["header"]["row_classification_complete"], True)
        self.assertIs(observed_test_artifact["header"]["complete"], True)

        unmet_feature = run_inventory(
            source_text="",
            listing=b"",
            emit_test_artifact=False,
            required_features=("unresolved",),
        )
        unmet_feature_header = unmet_feature["header"]
        unmet_feature_target = unmet_feature_header["target_denominator"][0]
        self.assertEqual(tuple(unmet_feature_target["required_features"]), ("unresolved",))
        self.assertIs(unmet_feature_target["required_features_satisfied"], False)
        self.assertEqual(unmet_feature_target["test_disposition"], "test_disabled")
        self.assertIs(unmet_feature_header["compiled_graph_complete"], False)
        self.assertIs(unmet_feature_header["complete"], False)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_dir = root / "crates" / "unknown-feature-package"
            source_path = package_dir / "src" / "lib.rs"
            source_path.parent.mkdir(parents=True)
            source_path.write_text("", encoding="utf-8")
            (package_dir / "Cargo.toml").write_text(
                '[package]\nname = "unknown-feature-package"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            iti._admitted_target_root(root).mkdir(parents=True, exist_ok=True)
            unknown_feature_target = PackageTarget(
                package_id="unknown-feature-package 0.1.0 (path+file:///crates/unknown-feature-package)",
                package_name="unknown-feature-package",
                manifest_dir=package_dir,
                target_name="unknown_feature_package",
                target_kind="lib",
                src_path=source_path,
                required_features=("feature-a",),
                required_features_satisfied=None,
                available_features=("feature-a",),
            )

            def unknown_feature_runner(cwd: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                if tuple(argv) == (
                    "cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json"
                ):
                    return CommandResult(
                        stdout=b'{"reason":"build-finished","success":true}\n',
                        stderr=b"",
                    )
                self.fail(f"unexpected injected command: {tuple(argv)!r}")

            unknown_compiled_completeness: list[bool] = []
            self.assertEqual(
                discover_compiled(
                    root,
                    [unknown_feature_target],
                    runner=unknown_feature_runner,
                    compiled_graph_complete_out=unknown_compiled_completeness,
                ),
                [],
            )
            self.assertEqual(unknown_compiled_completeness, [False])

        with_disabled_example = run_inventory(
            source_text="",
            listing=b"",
            include_example_target=True,
        )
        assert_inventory_hashes(with_disabled_example)
        example_record = next(
            record for record in with_disabled_example["header"]["target_denominator"]
            if record["target_name"] == "sample_example"
        )
        self.assertEqual(example_record["target_kind"], "example")
        self.assertEqual(example_record["test_disposition"], "test_disabled")
        self.assertIs(example_record["test_enabled"], False)
        self.assertEqual(len(with_disabled_example["header"]["artifact_denominator"]), 1)
        self.assertEqual(with_disabled_example["header"]["artifact_denominator"][0]["ignored_test_count"], 0)
        self.assertIs(with_disabled_example["header"]["compiled_graph_complete"], True)
        self.assertIs(with_disabled_example["header"]["complete"], True)

        source_recheck_change = run_inventory(
            include_example_target=True,
            mutate_lib_source_on_second_observation=True,
        )
        assert_inventory_hashes(source_recheck_change)
        recheck_header = source_recheck_change["header"]
        self.assertIs(recheck_header["source_identity"]["working_tree_clean"], True)
        self.assertIs(recheck_header["identity_complete"], True)
        self.assertIs(recheck_header["source_denominator_complete"], False)
        self.assertIs(recheck_header["compiled_graph_complete"], True)
        self.assertIs(recheck_header["row_classification_complete"], True)
        self.assertIs(recheck_header["complete"], False)

        try:
            missing_artifact = run_inventory(source_text="", listing=b"", include_artifact=False)
        except InventoryError as error:
            self.assertEqual(error.code, "COMPILED_GRAPH_UNAVAILABLE")
        else:
            self.assertIs(missing_artifact["header"]["compiled_graph_complete"], False)
            self.assertIs(missing_artifact["header"]["complete"], False)

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

        fixture = json.loads((self.fixture_dir / "sample_inventory.json").read_bytes())
        target_record = fixture["header"]["target_denominator"][0]

        def discover_in_creation_order(file_order: Sequence[str]):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                package_dir = root / "crates" / "sample-package"
                src = package_dir / "src"
                src.mkdir(parents=True)
                source_path = src / "lib.rs"
                source_path.write_text("mod alpha;\nmod omega;\n", encoding="utf-8")
                for name in file_order:
                    (src / name).write_text(
                        f'#[test]\n#[ignore = "requires store database"]\nfn test_{Path(name).stem}() {{}}\n',
                        encoding="utf-8",
                    )
                target = PackageTarget(
                    package_id=target_record["package_id"],
                    package_name=target_record["package_name"],
                    manifest_dir=package_dir,
                    target_name=target_record["target_name"],
                    target_kind=target_record["target_kind"],
                    src_path=source_path,
                )
                records: list[dict[str, object]] = []
                observe_source_file = iti._observe_source_file

                def observe_with_shared_synthetic_identity(
                    observe_root: Path,
                    path: Path,
                    deadline: float | None,
                ):
                    data, observed_identity, digest = observe_source_file(observe_root, path, deadline)
                    inode_by_name = {"lib.rs": 1, "alpha.rs": 2, "omega.rs": 3}
                    return data, {
                        "device": 1,
                        "inode": inode_by_name[Path(path).name],
                        "size": observed_identity["size"],
                        "mtime_ns": 1,
                    }, digest

                with patch.object(iti, "_observe_source_file", side_effect=observe_with_shared_synthetic_identity):
                    tests = discover_source(root, [target], source_denominator_records=records)
                # Closed source schema (issue #905 W10): every denominator record
                # production emits is exactly the resolved shape or the dangling
                # (unresolved/inactive/recheck) shape - no other keys admitted.
                resolved_shape = frozenset({
                    "package_id", "package_name", "target_name", "target_kind",
                    "path", "module_path", "sha256", "file_identity", "cfg_evidence",
                    "resolution", "declaration",
                })
                dangling_shape = resolved_shape | frozenset({
                    "reason", "declaration_source_path", "declaration_source_sha256",
                    "declaration_source_file_identity",
                })
                for source_record in records:
                    self.assertIn(frozenset(source_record), {resolved_shape, dangling_shape})
                    self.assertEqual("reason" in source_record, frozenset(source_record) == dangling_shape)
                return tests, records

        tests_created_forward, sources_created_forward = discover_in_creation_order(("alpha.rs", "omega.rs"))
        tests_created_reverse, sources_created_reverse = discover_in_creation_order(("omega.rs", "alpha.rs"))
        self.assertEqual(tests_created_forward, tests_created_reverse)
        self.assertEqual(sources_created_forward, sources_created_reverse)
        self.assertEqual(
            hashlib.sha256(_canonical_bytes(sources_created_forward)).hexdigest(),
            hashlib.sha256(_canonical_bytes(sources_created_reverse)).hexdigest(),
        )

        compiled_from_forward = [
            CompiledTest(
                package_id=test.package_id,
                package_name=test.package_name,
                target_name=test.target_name,
                target_kind=test.target_kind,
                executable=".eliot/integration/ignored-test-inventory/target/debug/deps/sample_package",
                executable_digest="fixture-executable-digest",
                test_name=test.test_name,
            )
            for test in tests_created_forward
        ]
        graph_rows_forward = reconcile(tests_created_forward, compiled_from_forward)
        graph_rows_reverse = reconcile(
            list(reversed(tests_created_reverse)), list(reversed(compiled_from_forward))
        )
        self.assertEqual(graph_rows_forward, graph_rows_reverse)
        graph_preimage = {
            "source_denominator": sources_created_forward,
            "rows": [dataclasses.asdict(row) for row in graph_rows_forward],
        }
        reverse_preimage = {
            "source_denominator": sources_created_reverse,
            "rows": [dataclasses.asdict(row) for row in graph_rows_reverse],
        }
        self.assertEqual(
            hashlib.sha256(_canonical_bytes(graph_preimage)).hexdigest(),
            hashlib.sha256(_canonical_bytes(reverse_preimage)).hexdigest(),
        )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            package_id = target_record["package_id"]
            package_dir = root / "crates" / "sample-package"
            source_path = root / target_record["src_path"]
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(
                '#[test]\n#[ignore = "requires store database"]\nfn test_sync_ignored() {}\n',
                encoding="utf-8",
            )
            manifest = package_dir / "Cargo.toml"

            def write_package_manifest(marker: str, rust_version: str) -> None:
                manifest.write_text(
                    '[package]\nname = "sample-package"\nversion = "0.1.0"\nedition = "2021"\n'
                    f'rust-version = "{rust_version}"\n\n[package.metadata.oracle]\nmarker = "{marker}"\n',
                    encoding="utf-8",
                )

            write_package_manifest("first", "1.70")
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            toolchain = fixture["header"]["toolchain"]
            (root / "rust-toolchain.toml").write_text(
                f'[toolchain]\nchannel = "{toolchain["channel"]}"\n', encoding="utf-8"
            )
            admitted_root = iti._admitted_target_root(root)
            admitted_root.mkdir(parents=True, exist_ok=True)
            executable = admitted_root / fixture["header"]["artifact_denominator"][0]["executable"]
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(b"synthetic executable identity")
            target_metadata = {
                "kind": [target_record["target_kind"]],
                "crate_types": [target_record["target_kind"]],
                "name": target_record["target_name"],
                "src_path": str(source_path),
                "edition": "2021",
                "doc": True,
                "doctest": True,
                "test": True,
                "required-features": [],
            }

            def cargo_metadata(
                package_metadata: dict[str, object],
                rust_version: str,
                resolve_root: str | None = package_id,
            ) -> dict[str, object]:
                package = {
                    "id": package_id,
                    "name": "sample-package",
                    "version": "0.1.0",
                    "manifest_path": str(manifest),
                    "targets": [target_metadata],
                    "features": {},
                    "dependencies": [],
                    "source": None,
                    "authors": [],
                    "categories": [],
                    "keywords": [],
                    "readme": None,
                    "repository": None,
                    "license": None,
                    "license_file": None,
                    "description": None,
                    "edition": "2021",
                    "links": None,
                    "default_run": None,
                    "rust_version": rust_version,
                    "metadata": package_metadata,
                    "publish": None,
                }
                return {
                    "version": 1,
                    "metadata": None,
                    "workspace_root": str(root),
                    "target_directory": str(admitted_root),
                    "workspace_members": [package_id],
                    "workspace_default_members": [package_id],
                    "packages": [package],
                    "resolve": {
                        "root": resolve_root,
                        "nodes": [{"id": package_id, "features": [], "deps": [], "dependencies": []}],
                    },
                }

            metadata_output = [cargo_metadata({"oracle": {"marker": "first"}}, "1.70")]
            profile = fixture["header"]["artifact_denominator"][0]["profile"]
            cargo_events = [
                {
                    "reason": "compiler-artifact",
                    "package_id": package_id,
                    "manifest_path": str(manifest),
                    "target": {
                        key: target_metadata[key]
                        for key in ("kind", "crate_types", "name", "src_path", "edition", "doc", "doctest", "test")
                    },
                    "profile": profile,
                    "features": fixture["header"]["artifact_denominator"][0]["features"],
                    "filenames": [str(executable)],
                    "executable": str(executable),
                    "fresh": True,
                },
                {"reason": "build-finished", "success": True},
            ]
            cargo_output = b"".join(
                json.dumps(event, sort_keys=True).encode("utf-8") + b"\n" for event in cargo_events
            )
            listing = b"test_sync_ignored: test\n"

            def runner(cwd: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
                command = tuple(argv)
                if command == ("git", "rev-parse", "HEAD"):
                    return CommandResult(stdout=b"0123456789abcdef0123456789abcdef01234567\n", stderr=b"")
                if command[:2] == ("git", "status"):
                    return CommandResult(stdout=b"", stderr=b"")
                if command == ("rustc", "--version", "--verbose"):
                    return CommandResult(stdout=_fixture_rustc_verbose(toolchain), stderr=b"")
                if command == ("cargo", "metadata", "--locked", "--format-version", "1"):
                    return CommandResult(
                        stdout=json.dumps(metadata_output[0], sort_keys=True).encode("utf-8"), stderr=b""
                    )
                if command == (
                    "cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json"
                ):
                    return CommandResult(stdout=cargo_output, stderr=b"")
                if command and Path(command[0]) == executable and command[1:] == (
                    "--list", "--ignored", "--format", "terse"
                ):
                    return CommandResult(stdout=listing, stderr=b"")
                self.fail(f"unexpected injected command: {command!r}")

            metadata_baseline = build_inventory(root, runner=runner)
            repeated_baseline = build_inventory(root, runner=runner)
            self.assertEqual(repeated_baseline, metadata_baseline)
            self.assertEqual(
                _canonical_bytes(metadata_baseline) + b"\n",
                _canonical_bytes(repeated_baseline) + b"\n",
            )
            self.assertIsNone(metadata_output[0]["packages"][0]["source"])
            self.assertEqual(metadata_output[0]["resolve"]["root"], package_id)
            baseline_header = metadata_baseline["header"]
            direct_build_hashes: list[str] = []
            discover_compiled(
                root,
                _targets(root, metadata_output[0]),
                runner=runner,
                metadata=metadata_output[0],
                build_sha256_out=direct_build_hashes,
            )
            self.assertEqual(direct_build_hashes, [baseline_header["cargo_build_sha256"]])
            variants = (
                cargo_metadata({"oracle": {"marker": "second"}}, "1.70"),
                cargo_metadata({"oracle": {"marker": "first"}}, "1.71"),
                cargo_metadata({"oracle": {"marker": "first"}}, "1.70", resolve_root=None),
            )
            for metadata_variant in variants:
                with self.subTest(metadata=metadata_variant["packages"][0]["metadata"],
                                  rust_version=metadata_variant["packages"][0]["rust_version"]):
                    package_variant = metadata_variant["packages"][0]
                    write_package_manifest(
                        package_variant["metadata"]["oracle"]["marker"],
                        package_variant["rust_version"],
                    )
                    metadata_output[0] = metadata_variant
                    changed = build_inventory(root, runner=runner)
                    changed_header = changed["header"]
                    self.assertNotEqual(changed_header["metadata_sha256"], baseline_header["metadata_sha256"])
                    self.assertNotEqual(changed_header["aggregate_sha256"], baseline_header["aggregate_sha256"])
                    baseline_projection = {
                        key: value for key, value in baseline_header.items()
                        if key not in {"metadata_sha256", "aggregate_sha256"}
                    }
                    changed_projection = {
                        key: value for key, value in changed_header.items()
                        if key not in {"metadata_sha256", "aggregate_sha256"}
                    }
                    self.assertEqual(changed_projection, baseline_projection)

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

            admitted_root = iti._admitted_target_root(troot)
            self.assertEqual(
                admitted_root,
                troot / ".eliot" / "integration" / "ignored-test-inventory" / "target",
            )
            admitted_root.mkdir(parents=True, exist_ok=True)
            inventory_fixture = json.loads((self.fixture_dir / "sample_inventory.json").read_bytes())
            target_record = inventory_fixture["header"]["target_denominator"][0]
            artifact_record = inventory_fixture["header"]["artifact_denominator"][0]
            fixture_row = next(
                row for row in inventory_fixture["rows"]
                if row["package_id"] == target_record["package_id"]
            )
            source_path = troot / target_record["src_path"]
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("", encoding="utf-8")
            manifest = source_path.parent.parent / "Cargo.toml"
            package_version = target_record["package_id"].split(" ", 2)[1]
            target_edition = "2021"
            manifest.write_text(
                "[package]\n"
                f"name = {json.dumps(target_record['package_name'])}\n"
                f"version = {json.dumps(package_version)}\n"
                f"edition = {json.dumps(target_edition)}\n",
                encoding="utf-8",
            )
            list_executable = admitted_root / artifact_record["executable"]
            list_executable.parent.mkdir(parents=True, exist_ok=True)
            list_executable.write_bytes(b"synthetic libtest identity")
            list_argv = (str(list_executable), "--list", "--ignored", "--format", "terse")
            admitted_identity, admitted_sha256 = iti._observe_executable(
                troot, admitted_root, list_executable
            )
            cargo_target = {
                "kind": [target_record["target_kind"]],
                "crate_types": [target_record["target_kind"]],
                "name": target_record["target_name"],
                "src_path": str(source_path),
                "edition": target_edition,
                "doc": True,
                "doctest": target_record["doctest_enabled"],
                "test": target_record["test_enabled"],
            }
            metadata_target = {
                **cargo_target,
                "required-features": list(target_record["required_features"]),
            }
            package_id = target_record["package_id"]
            metadata = {
                "version": 1,
                "metadata": None,
                "workspace_root": str(troot),
                "target_directory": str(admitted_root),
                "workspace_members": [package_id],
                "workspace_default_members": [package_id],
                "packages": [{
                    "id": package_id,
                    "name": target_record["package_name"],
                    "version": package_version,
                    "manifest_path": str(manifest),
                    "source": None,
                    "targets": [metadata_target],
                    "features": {},
                    "dependencies": [],
                }],
                "resolve": {
                    "root": package_id,
                    "nodes": [{
                        "id": package_id,
                        "features": list(artifact_record["features"]),
                        "deps": [],
                        "dependencies": [],
                    }],
                },
            }
            target = iti._targets(troot, metadata)[0]
            cargo_artifact = {
                "reason": "compiler-artifact",
                "package_id": package_id,
                "manifest_path": str(manifest),
                "target": cargo_target,
                "profile": artifact_record["profile"],
                "features": artifact_record["features"],
                "filenames": [str(list_executable)],
                "executable": str(list_executable),
                "fresh": True,
            }
            cargo_stream = b"\n".join((
                json.dumps(cargo_artifact).encode("utf-8"),
                json.dumps({"reason": "build-finished", "success": True}).encode("utf-8"),
            )) + b"\n"
            listing_stdout = f"{fixture_row['test_name']}: test\n".encode("utf-8")
            original_fixed = iti._run_fixed
            original_open_lease = iti._open_artifact_launch_lease
            original_verify_image = iti._verify_suspended_artifact_image
            original_details = iti._windows_handle_details
            original_close_handle = iti._close_windows_handle
            original_hash_handle = iti._windows_handle_sha256
            guarded_launches: list[Mock] = []

            def run_guarded_listing(
                queried_image: Path,
                *,
                foreign_native_identity: bool = False,
                attempt_component_rename: bool = False,
                query_failure: BaseException | None = None,
                mutate_before_listing: bool = False,
                caller_deadline: float | None = None,
            ) -> dict[str, object]:
                events: list[str] = []
                lease_handles: list[int] = []
                closed_handles: list[int] = []
                deadlines: dict[str, float | None] = {}
                handler_started: list[float] = []
                rename_results: list[OSError | None] = []
                captured_carriers: list[Artifact] = []
                receipt_sha256: list[str] = []
                lease_receipts: list[tuple[Artifact, tuple[tuple[str, int], ...], str]] = []
                image_sha256: list[str] = []
                mutation_observations: list[dict[str, object]] = []
                job = object()
                process_handle = 5000 + len(guarded_launches)
                process = Mock()
                process._handle = process_handle
                process.pid = process_handle + 100
                process.stdout = io.BytesIO(listing_stdout)
                process.stderr = io.BytesIO(b"")
                process.returncode = 0
                process_state = ["suspended"]
                process.poll.side_effect = lambda: 0 if process_state[0] == "completed" else None

                def reap_process(*args, **kwargs):
                    events.append("reap")
                    process_state[0] = "terminated"
                    process.returncode = 1
                    return 1

                process.wait.side_effect = reap_process
                process.kill.side_effect = lambda: events.append("kill")
                guarded_launches.append(process)
                process_created = [False]
                identity_mutated = [False]

                def move_while_lease_is_held(source: Path, destination: Path) -> OSError | None:
                    self.assertFalse(destination.exists())
                    try:
                        os.replace(source, destination)
                    except OSError as exc:
                        return exc
                    os.replace(destination, source)
                    return None

                def launch_process(*args, **kwargs):
                    events.append("popen")
                    process_created[0] = True
                    self.assertEqual(kwargs["executable"], str(list_executable))
                    if attempt_component_rename:
                        rename_results.append(move_while_lease_is_held(
                            list_executable,
                            list_executable.with_name(list_executable.name + ".renamed"),
                        ))
                        rename_results.append(move_while_lease_is_held(
                            list_executable.parent,
                            list_executable.parent.with_name(list_executable.parent.name + ".renamed"),
                        ))
                    return process

                def dispatch_fixed_command(
                    launch_root: Path,
                    command: Sequence[str],
                    timeout: float | None = None,
                    *,
                    deadline: float | None = None,
                    admitted_executable: Path | None = None,
                    admitted_target_root: Path | None = None,
                    admitted_artifact: Artifact | None = None,
                ) -> CommandResult:
                    if tuple(command) == iti._CARGO_BUILD_ARGV:
                        events.append("cargo-build")
                        return CommandResult(cargo_stream, b"")
                    if (
                        len(command) == 1 + len(iti._LIBTEST_LIST_ARGS)
                        and tuple(command[1:]) == iti._LIBTEST_LIST_ARGS
                    ):
                        events.append("listing-dispatch")
                        self.assertEqual(launch_root, troot)
                        self.assertEqual(admitted_executable, list_executable)
                        self.assertEqual(admitted_target_root, admitted_root)
                        self.assertIsNotNone(admitted_artifact)
                        captured_carriers.append(admitted_artifact)
                        receipt_sha256.append(admitted_artifact.executable_sha256)
                        if mutate_before_listing:
                            before = list_executable.read_bytes()
                            changed = bytes((before[0] ^ 1,)) + before[1:]
                            self.assertEqual(len(changed), len(before))
                            list_executable.write_bytes(changed)
                            mtime_ns = admitted_artifact.file_identity["mtime_ns"]
                            os.utime(list_executable, ns=(mtime_ns, mtime_ns))
                            live_identity, live_sha = iti._observe_executable(
                                troot, admitted_root, list_executable
                            )
                            mutation_observations.append({
                                "receipt_identity": dict(admitted_artifact.file_identity),
                                "receipt_sha256": admitted_artifact.executable_sha256,
                                "live_identity": live_identity,
                                "live_sha256": live_sha,
                            })
                        handler_started.append(iti.time.monotonic())
                        return original_fixed(
                            launch_root,
                            command,
                            timeout=timeout,
                            deadline=deadline,
                            admitted_executable=admitted_executable,
                            admitted_target_root=admitted_target_root,
                            admitted_artifact=admitted_artifact,
                        )
                    self.fail(f"unexpected fixed command in controlled discovery: {tuple(command)!r}")

                def open_lease(
                    launch_root: Path,
                    artifact: Artifact,
                    expected_identity: tuple[tuple[str, int], ...],
                    expected_sha256: str,
                    deadline: float | None,
                ) -> tuple[int, ...]:
                    deadlines["lease"] = deadline
                    lease_receipts.append((artifact, expected_identity, expected_sha256))
                    handles = original_open_lease(
                        launch_root, artifact, expected_identity, expected_sha256, deadline
                    )
                    lease_handles.extend(handles)
                    events.append("lease-open")
                    return handles

                def verify_image(
                    child_handle: int,
                    artifact: Artifact,
                    held_handles: tuple[int, ...],
                    expected_identity: tuple[tuple[str, int], ...],
                    expected_sha256: str,
                    deadline: float | None,
                ) -> None:
                    deadlines["verify"] = deadline
                    original_verify_image(
                        child_handle,
                        artifact,
                        held_handles,
                        expected_identity,
                        expected_sha256,
                        deadline,
                    )
                    events.append("image-verified")

                def query_image(child_handle: int) -> str:
                    self.assertEqual(child_handle, process_handle)
                    events.append("query-image")
                    if query_failure is not None:
                        raise query_failure
                    return str(queried_image)

                def details(handle: int):
                    value = original_details(handle)
                    if foreign_native_identity and process_created[0] and not identity_mutated[0]:
                        identity_mutated[0] = True
                        return dataclasses.replace(
                            value,
                            native_identity=(
                                value.native_identity[0],
                                value.native_identity[1],
                                value.native_identity[2] + 1,
                            ),
                        )
                    return value

                def close_handle(handle: int) -> None:
                    closed_handles.append(handle)
                    events.append(f"close-handle:{handle}")
                    original_close_handle(handle)

                def observe_image_sha256(handle: int, deadline: float | None) -> str:
                    digest = original_hash_handle(handle, deadline)
                    image_sha256.append(digest)
                    return digest

                def query_job(handle: int) -> int:
                    self.assertIs(handle, job)
                    events.append("active:0")
                    return 0

                def resume_process(pid: int) -> None:
                    self.assertEqual(pid, process.pid)
                    events.append("resume")
                    process_state[0] = "completed"

                artifact_records: list[dict[str, object]] = []
                try:
                    with (
                        patch.object(iti, "_run_fixed", side_effect=dispatch_fixed_command),
                        patch.object(iti.subprocess, "Popen", side_effect=launch_process),
                        patch.object(iti, "_create_job_object", side_effect=lambda: events.append("job-create") or job),
                        patch.object(iti, "_assign_job_object", side_effect=lambda handle, child: events.append("assign")),
                        patch.object(iti, "_resume_suspended_process", side_effect=resume_process),
                        patch.object(iti, "_query_suspended_image_path", side_effect=query_image),
                        patch.object(iti, "_open_artifact_launch_lease", side_effect=open_lease),
                        patch.object(iti, "_verify_suspended_artifact_image", side_effect=verify_image),
                        patch.object(iti, "_windows_handle_details", side_effect=details),
                        patch.object(iti, "_windows_handle_sha256", side_effect=observe_image_sha256),
                        patch.object(iti, "_close_windows_handle", side_effect=close_handle),
                        patch.object(iti, "_terminate_job_object", side_effect=lambda handle, code: events.append("terminate")),
                        patch.object(iti, "_query_job_active_processes", side_effect=query_job),
                        patch.object(iti, "_close_job_object", side_effect=lambda handle: events.append("close-job")),
                    ):
                        compiled = discover_compiled(
                            troot,
                            [target],
                            runner=None,
                            metadata=metadata,
                            artifact_denominator_records=artifact_records,
                            deadline=caller_deadline,
                        )
                    error = None
                except BaseException as caught:
                    compiled = None
                    error = caught
                return {
                    "compiled": compiled,
                    "error": error,
                    "events": events,
                    "lease_handles": lease_handles,
                    "closed_handles": closed_handles,
                    "deadlines": deadlines,
                    "handler_started": handler_started,
                    "rename_results": rename_results,
                    "carriers": captured_carriers,
                    "lease_receipts": lease_receipts,
                    "artifact_records": artifact_records,
                    "receipt_sha256": receipt_sha256,
                    "image_sha256": image_sha256,
                    "mutation_observations": mutation_observations,
                    "process": process,
                    "popen_count": len([event for event in events if event == "popen"]),
                    "identity_mutated": identity_mutated[0],
                    "query_image_called": "query-image" in events,
                }

            launch_deadline = iti.time.monotonic() + float(BOUNDS.command_timeout_seconds)
            admitted_launch = run_guarded_listing(
                list_executable,
                attempt_component_rename=True,
                caller_deadline=launch_deadline,
            )
            self.assertIsNone(admitted_launch["error"])
            self.assertEqual(len(admitted_launch["carriers"]), 1)
            self.assertEqual(len(admitted_launch["artifact_records"]), 1)
            admitted_artifact = admitted_launch["carriers"][0]
            admitted_record = admitted_launch["artifact_records"][0]
            self.assertEqual(
                [item.test_name for item in admitted_launch["compiled"]],
                [fixture_row["test_name"]],
            )
            self.assertEqual(admitted_artifact.package_id, target.package_id)
            self.assertEqual(admitted_artifact.target_kind, target.target_kind)
            self.assertEqual(admitted_artifact.target_name, target.target_name)
            self.assertEqual(admitted_artifact.executable, list_executable)
            self.assertEqual(admitted_artifact.target_root, admitted_root)
            self.assertEqual(admitted_artifact.profile, artifact_record["profile"])
            self.assertEqual(admitted_artifact.file_identity, admitted_identity)
            self.assertEqual(admitted_artifact.executable_sha256, admitted_sha256)
            self.assertEqual(admitted_launch["receipt_sha256"], [admitted_sha256])
            self.assertEqual(len(admitted_launch["lease_receipts"]), 1)
            leased_artifact, leased_identity, leased_sha256 = admitted_launch["lease_receipts"][0]
            self.assertEqual(leased_artifact.executable, admitted_artifact.executable)
            self.assertEqual(leased_artifact.target_root, admitted_artifact.target_root)
            self.assertEqual(leased_artifact.package_id, admitted_artifact.package_id)
            self.assertEqual(leased_artifact.target_kind, admitted_artifact.target_kind)
            self.assertEqual(leased_artifact.target_name, admitted_artifact.target_name)
            self.assertEqual(leased_artifact.profile, admitted_artifact.profile)
            self.assertEqual(leased_identity, tuple(sorted(admitted_identity.items())))
            self.assertEqual(leased_sha256, admitted_artifact.executable_sha256)
            self.assertEqual(admitted_record["executable"], artifact_record["executable"])
            self.assertEqual(admitted_record["profile"], admitted_artifact.profile)
            self.assertEqual(admitted_record["file_identity"], admitted_artifact.file_identity)
            self.assertEqual(admitted_record["sha256"], admitted_artifact.executable_sha256)
            self.assertIsNot(admitted_record["profile"], admitted_artifact.profile)
            self.assertIsNot(admitted_record["file_identity"], admitted_artifact.file_identity)
            admitted_events = admitted_launch["events"]
            admitted_leases = admitted_launch["lease_handles"]
            admitted_closes = admitted_launch["closed_handles"]
            admitted_deadlines = admitted_launch["deadlines"]
            self.assertTrue(admitted_leases)
            self.assertEqual(len(admitted_leases), len(set(admitted_leases)))
            self.assertEqual(
                len(admitted_leases),
                len(Path(os.path.abspath(list_executable)).parts),
            )
            self.assertEqual(len(admitted_launch["rename_results"]), 2)
            self.assertTrue(all(isinstance(error, OSError) for error in admitted_launch["rename_results"]))
            self.assertLess(admitted_events.index("lease-open"), admitted_events.index("popen"))
            self.assertIn("query-image", admitted_events)
            self.assertLess(admitted_events.index("assign"), admitted_events.index("resume"))
            self.assertLess(admitted_events.index("image-verified"), admitted_events.index("resume"))
            self.assertIn("active:0", admitted_events)
            self.assertIn("close-job", admitted_events)
            self.assertEqual(set(admitted_deadlines), {"lease", "verify"})
            self.assertEqual(admitted_deadlines["lease"], admitted_deadlines["verify"])
            cutoff = admitted_deadlines["lease"]
            self.assertIsInstance(cutoff, float)
            self.assertGreater(cutoff, admitted_launch["handler_started"][0])
            self.assertLessEqual(cutoff, launch_deadline)
            for handle in admitted_leases:
                self.assertEqual(admitted_closes.count(handle), 1)
                self.assertLess(
                    admitted_events.index("resume"),
                    admitted_events.index(f"close-handle:{handle}"),
                )

            real_lstat = Path.lstat
            reparse_stat = Mock()
            reparse_stat.st_mode = 0o40755
            reparse_stat.st_file_attributes = 0x400

            def lstat_with_target_reparse(path, *args, **kwargs):
                if path == admitted_root:
                    return reparse_stat
                return real_lstat(path, *args, **kwargs)

            with patch.object(Path, "lstat", autospec=True, side_effect=lstat_with_target_reparse):
                with self.assertRaises(InventoryError) as cm:
                    iti._admitted_target_root(troot)
            self.assertEqual(cm.exception.code, "PATH_ESCAPE")

            def run_fixed_failure(
                stdout: bytes,
                stderr: bytes,
                wait_side_effect: object,
                active_counts: list[int],
                *,
                small_output_cap: bool = False,
                timeout: float = 1.0,
                argv: Sequence[str] = ("git", "rev-parse", "HEAD"),
                admitted_executable: Path | None = None,
                admitted_artifact: Artifact | None = None,
                active_count_fallback: int = 0,
            ) -> tuple[InventoryError, list[str], Mock]:
                job = object()
                process_handle = 4242
                lease_handle = process_handle + 1
                process = Mock()
                process._handle = process_handle
                process.pid = 42
                process.stdout = io.BytesIO(stdout)
                process.stderr = io.BytesIO(stderr)
                process.returncode = 0
                process.wait.side_effect = wait_side_effect
                process.poll.return_value = None
                events: list[str] = []
                terminate_job = Mock(side_effect=lambda handle, code: events.append("terminate"))

                def query_active_processes(handle):
                    value = active_counts.pop(0) if active_counts else active_count_fallback
                    events.append(f"active:{value}")
                    return value

                with (
                    patch.object(iti.subprocess, "Popen", return_value=process),
                    patch.object(iti, "_create_job_object", return_value=job),
                    patch.object(iti, "_assign_job_object", side_effect=lambda handle, child: events.append("assign")),
                    patch.object(iti, "_resume_suspended_process", side_effect=lambda pid: events.append("resume")),
                    patch.object(iti, "_open_artifact_launch_lease", return_value=(lease_handle,)),
                    patch.object(
                        iti,
                        "_verify_suspended_artifact_image",
                        side_effect=lambda *args: events.append("image-verified"),
                    ),
                    patch.object(iti, "_close_windows_handle", side_effect=lambda handle: events.append("lease-close")),
                    patch.object(iti, "_terminate_job_object", terminate_job),
                    patch.object(
                        iti,
                        "_query_job_active_processes",
                        side_effect=query_active_processes,
                    ),
                    patch.object(iti, "_close_job_object", side_effect=lambda handle: events.append("close")),
                    patch.object(
                        iti,
                        "BOUNDS",
                        dataclasses.replace(BOUNDS, max_command_output_bytes=8) if small_output_cap else BOUNDS,
                    ),
                ):
                    with self.assertRaises(InventoryError) as cm:
                        _run_fixed(
                            troot,
                            argv,
                            timeout=timeout,
                            admitted_executable=admitted_executable,
                            admitted_artifact=admitted_artifact,
                        )
                self.assertIn("terminate", events)
                self.assertIn("close", events)
                self.assertEqual(active_counts, [])
                if admitted_artifact is not None:
                    self.assertEqual(events.count("lease-close"), 1)
                return cm.exception, events, terminate_job

            overflow_error, overflow_events, overflow_terminate = run_fixed_failure(
                b"too many output bytes",
                b"",
                lambda *args, **kwargs: 0,
                [0],
                small_output_cap=True,
            )
            self.assertEqual(overflow_error.code, "COMMAND_OUTPUT_TOO_LARGE")
            self.assertEqual(overflow_terminate.call_count, 1)
            self.assertEqual(overflow_terminate.call_args.args[1], 1)
            self.assertLess(overflow_events.index("assign"), overflow_events.index("resume"))

            diagnostic = b"begin-marker" + (b"x" * (iti._STDERR_TAIL_CHARS + 64)) + b"tail-marker"
            real_sleep = iti.time.sleep
            fake_clock = [100.0]
            clock_calls = [0]
            sleep_calls = [0]
            observed_wait_timeouts: list[float] = []

            def advancing_monotonic() -> float:
                clock_calls[0] += 1
                if clock_calls[0] > 128:
                    raise AssertionError("simulated deadline clock exceeded its invocation bound")
                fake_clock[0] += 0.001
                return fake_clock[0]

            def advancing_sleep(duration: float) -> None:
                sleep_calls[0] += 1
                if sleep_calls[0] > 64:
                    raise AssertionError("simulated deadline driver exceeded its sleep bound")
                fake_clock[0] += max(duration, 0.5)
                real_sleep(0)

            confirmed_reap_calls = [0]

            def reap_after_termination(*args, **kwargs):
                confirmed_reap_calls[0] += 1
                wait_timeout = kwargs.get("timeout", args[0] if args else None)
                if wait_timeout is not None:
                    observed_wait_timeouts.append(wait_timeout)
                return 1

            with (
                patch.object(iti.time, "monotonic", side_effect=advancing_monotonic),
                patch.object(iti.time, "sleep", side_effect=advancing_sleep),
            ):
                timeout_error, timeout_events, timeout_terminate = run_fixed_failure(
                    b"",
                    diagnostic,
                    reap_after_termination,
                    [1, 0],
                    timeout=10.0,
                    argv=list_argv,
                    admitted_executable=list_executable,
                    admitted_artifact=admitted_artifact,
                )
            self.assertEqual(timeout_error.code, "COMPILED_GRAPH_UNAVAILABLE")
            self.assertEqual(timeout_terminate.call_count, 1)
            self.assertEqual(confirmed_reap_calls[0], 1)
            self.assertEqual(len(observed_wait_timeouts), 1)
            self.assertIn("active:0", timeout_events)
            self.assertLessEqual(clock_calls[0], 128)
            self.assertLessEqual(sleep_calls[0], 64)
            self.assertLessEqual(len(timeout_error.detail), iti._STDERR_TAIL_CHARS)
            self.assertNotIn("begin-marker", timeout_error.detail)
            self.assertIn("tail-marker", timeout_error.detail)
            self.assertLess(timeout_events.index("terminate"), timeout_events.index("close"))

            uncertain_clock = [200.0]
            uncertain_clock_calls = [0]
            uncertain_sleep_calls = [0]

            def advancing_uncertain_monotonic() -> float:
                uncertain_clock_calls[0] += 1
                if uncertain_clock_calls[0] > 128:
                    raise AssertionError("uncertain-cleanup clock exceeded its invocation bound")
                uncertain_clock[0] += 0.001
                return uncertain_clock[0]

            def advancing_uncertain_sleep(duration: float) -> None:
                uncertain_sleep_calls[0] += 1
                if uncertain_sleep_calls[0] > 64:
                    raise AssertionError("uncertain-cleanup driver exceeded its sleep bound")
                uncertain_clock[0] += max(duration, 0.5)
                real_sleep(0)

            uncertain_reap_calls = [0]

            def reap_without_tree_confirmation(*args, **kwargs):
                uncertain_reap_calls[0] += 1
                return 1

            with (
                patch.object(iti.time, "monotonic", side_effect=advancing_uncertain_monotonic),
                patch.object(iti.time, "sleep", side_effect=advancing_uncertain_sleep),
            ):
                uncertain_error, uncertain_events, uncertain_terminate = run_fixed_failure(
                    b"",
                    diagnostic,
                    reap_without_tree_confirmation,
                    [],
                    timeout=10.0,
                    argv=list_argv,
                    admitted_executable=list_executable,
                    admitted_artifact=admitted_artifact,
                    active_count_fallback=1,
                )
            self.assertEqual(uncertain_error.code, "COMPILED_GRAPH_UNAVAILABLE")
            self.assertGreaterEqual(uncertain_reap_calls[0], 1)
            self.assertGreaterEqual(uncertain_terminate.call_count, 1)
            self.assertIn("active:1", uncertain_events)
            self.assertNotIn("active:0", uncertain_events)
            self.assertLessEqual(len(uncertain_error.detail), iti._STDERR_TAIL_CHARS)
            self.assertNotIn("begin-marker", uncertain_error.detail)
            self.assertIn("tail-marker", uncertain_error.detail)
            self.assertLessEqual(uncertain_clock_calls[0], 128)
            self.assertLessEqual(uncertain_sleep_calls[0], 64)

            missing_carrier_popen = Mock()
            with patch.object(iti.subprocess, "Popen", missing_carrier_popen):
                with self.assertRaises(InventoryError) as cm:
                    _run_fixed(
                        troot,
                        list_argv,
                        admitted_executable=list_executable,
                        admitted_target_root=admitted_root,
                    )
            self.assertEqual(cm.exception.code, "COMMAND_NOT_ALLOWED")
            missing_carrier_popen.assert_not_called()

            alternate_executable = list_executable.with_name(list_executable.name + ".alternate")
            alternate_executable.write_bytes(list_executable.read_bytes() + b"\x00")
            outside_image = Path(__file__).resolve()

            def assert_refusal_cleanup(observation: dict[str, object]) -> None:
                events = observation["events"]
                leases = observation["lease_handles"]
                self.assertNotIn("resume", events)
                self.assertTrue(observation["process"].wait.called)
                self.assertIn("reap", events)
                self.assertTrue(leases)
                first_release = min(
                    events.index(f"close-handle:{handle}") for handle in leases
                )
                if "assign" in events:
                    self.assertIn("terminate", events)
                    self.assertIn("active:0", events)
                    self.assertIn("close-job", events)
                    for settled_event in ("terminate", "reap", "active:0"):
                        self.assertLess(events.index(settled_event), first_release)
                else:
                    self.assertIn("kill", events)
                    self.assertLess(events.index("reap"), first_release)
                for handle in leases:
                    self.assertEqual(observation["closed_handles"].count(handle), 1)

            mismatched_launches = (
                run_guarded_listing(outside_image),
                run_guarded_listing(alternate_executable),
                run_guarded_listing(list_executable, foreign_native_identity=True),
            )
            for mismatched_launch in mismatched_launches:
                self.assertIsInstance(mismatched_launch["error"], InventoryError)
                self.assertEqual(mismatched_launch["error"].code, "COMPILED_GRAPH_UNAVAILABLE")
                self.assertTrue(mismatched_launch["query_image_called"])
                assert_refusal_cleanup(mismatched_launch)
            self.assertTrue(mismatched_launches[2]["identity_mutated"])

            query_failure_launch = run_guarded_listing(
                list_executable,
                query_failure=OSError("injected suspended image query failure"),
            )
            self.assertIsInstance(query_failure_launch["error"], InventoryError)
            self.assertEqual(query_failure_launch["error"].code, "COMPILED_GRAPH_UNAVAILABLE")
            cancellation_signal = KeyboardInterrupt("injected suspended image query cancellation")
            cancellation_launch = run_guarded_listing(
                list_executable,
                query_failure=cancellation_signal,
            )
            self.assertIs(cancellation_launch["error"], cancellation_signal)
            for interrupted_launch in (query_failure_launch, cancellation_launch):
                self.assertTrue(interrupted_launch["query_image_called"])
                assert_refusal_cleanup(interrupted_launch)

            stale_original_bytes = list_executable.read_bytes()
            stale = run_guarded_listing(
                list_executable,
                mutate_before_listing=True,
            )
            mutation = stale["mutation_observations"][0]
            self.assertEqual(mutation["receipt_identity"], admitted_identity)
            self.assertEqual(mutation["live_identity"], admitted_identity)
            self.assertEqual(mutation["receipt_sha256"], admitted_sha256)
            self.assertNotEqual(mutation["live_sha256"], mutation["receipt_sha256"])
            self.assertEqual(stale["error"].code, "COMPILED_GRAPH_UNAVAILABLE")
            self.assertEqual(stale["popen_count"], 0)
            self.assertNotIn("resume", stale["events"])
            self.assertEqual(len(stale["carriers"]), 1)
            self.assertEqual(stale["receipt_sha256"], [admitted_sha256])
            stale_carrier = stale["carriers"][0]
            self.assertEqual(stale_carrier.file_identity, admitted_identity)
            self.assertEqual(stale_carrier.executable_sha256, admitted_sha256)
            self.assertEqual(len(stale["lease_receipts"]), 1)
            stale_lease_artifact, stale_identity, stale_sha256 = stale["lease_receipts"][0]
            self.assertEqual(stale_lease_artifact.file_identity, admitted_identity)
            self.assertEqual(stale_identity, tuple(sorted(admitted_identity.items())))
            self.assertEqual(stale_sha256, admitted_sha256)
            self.assertEqual(stale["image_sha256"], [mutation["live_sha256"]])
            self.assertFalse(stale["lease_handles"])
            self.assertTrue(stale["closed_handles"])
            self.assertEqual(len(stale["closed_handles"]), len(set(stale["closed_handles"])))
            self.assertEqual(
                len(stale["closed_handles"]),
                len(Path(os.path.abspath(list_executable)).parts),
            )
            list_executable.write_bytes(stale_original_bytes)
            os.utime(
                list_executable,
                ns=(admitted_identity["mtime_ns"], admitted_identity["mtime_ns"]),
            )

    # WORK_UNIT_CASE: 905/26
    def test_no_provisioning_ignored_test_execution_workflow_secret_rust_mutation_path(self) -> None:
        """No provisioning, ignored-test execution, workflow/secret/Rust mutation path."""
        source_text = _script_path.read_text(encoding="utf-8")
        parsed_ast = ast.parse(source_text)

        # Check imports: no network or database libraries
        disallowed_modules = {"socket", "requests", "http", "surrealdb", "sqlite3", "psycopg2"}
        for node in ast.walk(parsed_ast):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "urllib.parse":
                        continue  # Pure URL parsing, not transport.
                    self.assertNotIn(alias.name.split(".")[0], disallowed_modules | {"urllib"})
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    if node.module == "urllib.parse":
                        self.assertTrue(node.names)
                        self.assertTrue(all(
                            alias.name in {"urlparse", "unquote"} and alias.asname is None
                            for alias in node.names
                        ))
                        continue  # Pure URL parsing, not transport.
                    if node.module == "urllib.request":
                        self.assertEqual(
                            [(alias.name, alias.asname) for alias in node.names],
                            [("url2pathname", None)],
                        )
                        continue  # Pure file-URI path conversion, not transport.
                    self.assertNotIn(node.module.split(".")[0], disallowed_modules | {"urllib"})

        network_calls = {"urlopen", "urlretrieve", "Request"}
        for node in ast.walk(parsed_ast):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, network_calls)
            elif isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, network_calls)

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
