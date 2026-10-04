"""Unit tests for crate reachability and support-neutral inventory (issue #1133)."""

from __future__ import annotations

import importlib.util
import io
import json
import dataclasses
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from datetime import date, timedelta
from unittest import mock

# Import scripts/crate_reachability_inventory.py dynamically
_script_path = Path(__file__).resolve().parents[1] / "crate_reachability_inventory.py"
_spec = importlib.util.spec_from_file_location("crate_reachability_inventory", _script_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {_script_path}")
cri = importlib.util.module_from_spec(_spec)
sys.modules["crate_reachability_inventory"] = cri
_spec.loader.exec_module(cri)

InventoryError = cri.InventoryError
BOUNDS = cri.BOUNDS
Bounds = cri.Bounds
ManifestClass = cri.ManifestClass
Reachability = cri.Reachability
SourceScope = cri.SourceScope
_mask_rust = cri._mask_rust
_sha256 = cri._sha256
_canonical_bytes = cri._canonical_bytes
_safe_output = cri._safe_output
_read_bytes = cri._read_bytes
run_self_tests = cri.run_self_tests
build_inventory = cri.build_inventory


class _StrictRunner:
    """Finite fixture command map; unexpected calls fail without spawning tools."""

    def __init__(self, responses: dict[tuple[str, ...], bytes | Exception]) -> None:
        self.responses = dict(responses)
        self.calls: list[tuple[str, ...]] = []

    def run(self, root: Path, argv: tuple[str, ...] | list[str]) -> bytes:
        command = tuple(argv)
        self.calls.append(command)
        if command not in self.responses:
            raise AssertionError(f"fixture runner received an undeclared command: {command!r}")
        response = self.responses[command]
        if isinstance(response, Exception):
            raise response
        return response


class _ForeignLockFailureRunner(_StrictRunner):
    """A declared metadata failure that leaves a lock created by the runner intact."""

    def __init__(
        self,
        responses: dict[tuple[str, ...], bytes | Exception],
        *,
        lock_command: tuple[str, ...],
        lock_relative_path: str,
        lock_bytes: bytes,
    ) -> None:
        super().__init__(responses)
        self.lock_command = lock_command
        self.lock_relative_path = lock_relative_path
        self.lock_bytes = lock_bytes

    def run(self, root: Path, argv: tuple[str, ...] | list[str]) -> bytes:
        command = tuple(argv)
        if command != self.lock_command:
            return super().run(root, argv)
        if command not in self.responses:
            raise AssertionError(f"fixture runner received an undeclared command: {command!r}")
        self.calls.append(command)
        lock_path = root / self.lock_relative_path
        if lock_path.exists():
            raise AssertionError(f"fixture expected no pre-existing lock at {lock_path}")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_bytes(self.lock_bytes)
        response = self.responses[command]
        if isinstance(response, Exception):
            raise response
        return response


_FIXTURE_HEAD = "8c2625a08c2cd65b8cbd7b4938185cb306428d6f"
_FIXTURE_REVISION = "2026-09-29.1"
_ROOT_MANIFESTS = (
    "Cargo.toml",
    "bins/eliot/Cargo.toml",
    "crates/foundation/eliot-contracts/Cargo.toml",
)
_METADATA_COMMAND = (
    "cargo",
    "metadata",
    "--locked",
    "--offline",
    "--all-features",
    "--format-version",
    "1",
)
_MEMBER_METADATA_COMMAND = (
    "cargo",
    "metadata",
    "--locked",
    "--offline",
    "--all-features",
    "--format-version",
    "1",
    "--manifest-path",
    "crates/foundation/eliot-contracts/Cargo.toml",
)
_I223_ADMISSION_FIELDS = (
    "affected_functional_cells_and_lifecycle_owners",
    "current_source_dependency_and_change_closure",
    "proposed_package_boundary",
    "public_contract_and_independent_test_entrypoint",
    "first_real_consumer_or_time_bounded_migration_facade",
    "source_maintenance_owner_and_vendor_type_boundary",
    "dependency_security_license_and_build_isolation",
    "expected_agent_workset_context_and_reverse_fanout_delta",
    "expected_compile_test_integration_and_release_cost_delta",
    "migration_reexport_rollback_removal_and_expiry",
    "counter_risks_merge_or_rejoin_condition",
    "evidence_status_and_review_owner",
)
_MANIFESTS_COMMAND = ("git", "ls-files", "-z", "--", "Cargo.toml", ":(glob)**/Cargo.toml")
_MODULES_COMMAND = ("git", "ls-files", "-z", "--", "module.toml", ":(glob)**/module.toml")


def _fixture_id(root: Path, member: str, package: str) -> str:
    manifest = (root / member / "Cargo.toml").as_posix()
    return f"path+file://{manifest}#{package}@0.1.0"


def _write_inventory_fixture(
    root: Path,
    *,
    dependency_kinds: tuple[dict[str, str | None], ...] | None = None,
    consumer_source: str = "fn main() {}\n",
    provider_source: str = "pub fn contract() {}\n",
    extra_sources: dict[str, str] | None = None,
    metadata_omits_provider: bool = False,
    provider_metadata: dict[str, object] | None = None,
) -> _StrictRunner:
    """Write a two-member, locked root fixture and return its finite command map."""
    root = root.resolve()
    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / ".eliot").mkdir(exist_ok=True)
    (root / "bins/eliot/src").mkdir(parents=True, exist_ok=True)
    (root / "crates/foundation/eliot-contracts/src").mkdir(parents=True, exist_ok=True)
    (root / "scripts/testdata/crate-reachability").mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nresolver = "3"\nmembers = ["bins/eliot", "crates/foundation/eliot-contracts"]\nexclude = []\n',
        encoding="utf-8",
    )
    (root / "bins/eliot/Cargo.toml").write_text(
        '[package]\nname = "eliot"\nversion = "0.1.0"\nedition = "2024"\n',
        encoding="utf-8",
    )
    (root / "crates/foundation/eliot-contracts/Cargo.toml").write_text(
        '[package]\nname = "eliot-contracts"\nversion = "0.1.0"\nedition = "2024"\n',
        encoding="utf-8",
    )
    (root / "bins/eliot/src/main.rs").write_bytes(consumer_source.encode("utf-8"))
    (root / "crates/foundation/eliot-contracts/src/lib.rs").write_bytes(provider_source.encode("utf-8"))
    for relative, source in (extra_sources or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
    (root / cri.DECISION_DATA_RELPATH).write_text(
        f'schema = "{cri.DECISION_SCHEMA}"\nrevision = "{_FIXTURE_REVISION}"\ndecision = []\nadmission_decision = []\n',
        encoding="utf-8",
    )

    consumer_id = _fixture_id(root, "bins/eliot", "eliot")
    provider_id = _fixture_id(root, "crates/foundation/eliot-contracts", "eliot-contracts")
    consumer = {
        "id": consumer_id,
        "name": "eliot",
        "version": "0.1.0",
        "manifest_path": str(root / "bins/eliot/Cargo.toml"),
        "source": None,
        "metadata": {},
        "targets": [
            {
                "name": "eliot",
                "kind": ["bin"],
                "crate_types": ["bin"],
                "src_path": str(root / "bins/eliot/src/main.rs"),
                "edition": "2024",
            }
        ],
    }
    provider_package: dict[str, object] = {
        "id": provider_id,
        "name": "eliot-contracts",
        "version": "0.1.0",
        "manifest_path": str(root / "crates/foundation/eliot-contracts/Cargo.toml"),
        "source": None,
        "metadata": provider_metadata or {},
        "targets": [
            {
                "name": "eliot_contracts",
                "kind": ["lib"],
                "crate_types": ["lib"],
                "src_path": str(root / "crates/foundation/eliot-contracts/src/lib.rs"),
                "edition": "2024",
            }
        ],
    }
    dep_kinds = list(dependency_kinds) if dependency_kinds is not None else [
        {"kind": "normal", "target": None},
        {"kind": "dev", "target": None},
        {"kind": "normal", "target": "cfg(windows)"},
    ]
    consumer_deps = (
        [
            {
                "pkg": provider_id,
                "name": "eliot_contracts",
                "dep_kinds": dep_kinds,
            }
        ]
        if dep_kinds
        else []
    )
    packages = [consumer, provider_package]
    members = [consumer_id, provider_id]
    if metadata_omits_provider:
        packages = [consumer]
        members = [consumer_id]
        consumer_deps = []
    metadata = {
        "packages": packages,
        "workspace_members": members,
        "workspace_default_members": members,
        "workspace_root": str(root),
        "resolve": {
            "nodes": [
                {"id": consumer_id, "deps": consumer_deps},
                *([] if metadata_omits_provider else [{"id": provider_id, "deps": []}]),
            ]
        },
    }
    responses = {
        _MANIFESTS_COMMAND: ("\x00".join(_ROOT_MANIFESTS) + "\x00").encode("utf-8"),
        _METADATA_COMMAND: json.dumps(metadata, sort_keys=True).encode("utf-8"),
        ("git", "rev-parse", "HEAD"): (_FIXTURE_HEAD + "\n").encode("ascii"),
        ("git", "status", "--porcelain=v1", "--untracked-files=no"): b"",
        ("cargo", "-Vv"): b"cargo fixture runner (not a toolchain claim)\n",
        ("rustc", "-Vv"): b"rustc fixture runner (not a toolchain claim)\n",
        _MODULES_COMMAND: b"",
    }
    if metadata_omits_provider:
        responses[_MEMBER_METADATA_COMMAND] = json.dumps(
            {
                "packages": [provider_package],
                "workspace_members": [provider_id],
                "workspace_default_members": [provider_id],
                "workspace_root": str(root),
                "resolve": {"nodes": [{"id": provider_id, "deps": []}]},
            },
            sort_keys=True,
        ).encode("utf-8")
    return _StrictRunner(responses)


def _canonical_supplier_fixture(root: Path) -> tuple[_StrictRunner, dict[str, object]]:
    """Materialize the current canonical #1721 record and its declared source pair."""
    root = root.resolve()
    source_root = _script_path.resolve().parents[1]
    registry_path = source_root / cri.DECISION_DATA_RELPATH
    registry_raw = registry_path.read_bytes()
    registry = tomllib.loads(registry_raw.decode("utf-8"))
    package_name = "eliot-dreamer-failure"
    record = next(item for item in registry[cri.ADMISSION_DATA_KEY] if item["package"] == package_name)
    module_relative = "crates/smart/eliot-dreamer-failure/module.toml"
    target_relative = "crates/smart/eliot-dreamer-failure"
    consumer_relative = "crates/governor/eliot-governor"
    proof_relative = "crates/smart/eliot-dreamer-failure/tests/failure.rs"
    consumer_source_relative = "crates/governor/eliot-governor/src/negative_memory_gate.rs"
    target_id = _fixture_id(root, target_relative, package_name)
    consumer_id = _fixture_id(root, consumer_relative, "eliot-governor")

    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / ".eliot").mkdir(exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nresolver = "3"\nmembers = ["'
        + target_relative
        + '", "'
        + consumer_relative
        + '"]\nexclude = []\n',
        encoding="utf-8",
    )
    for relative in (target_relative, consumer_relative):
        (root / relative).mkdir(parents=True, exist_ok=True)

    target_source_manifest = source_root / target_relative / "Cargo.toml"
    consumer_source_manifest = source_root / consumer_relative / "Cargo.toml"
    (root / target_relative / "Cargo.toml").write_bytes(target_source_manifest.read_bytes())
    (root / consumer_relative / "Cargo.toml").write_bytes(consumer_source_manifest.read_bytes())
    (root / module_relative).write_bytes((source_root / module_relative).read_bytes())
    (root / proof_relative).parent.mkdir(parents=True, exist_ok=True)
    (root / proof_relative).write_bytes((source_root / proof_relative).read_bytes())
    consumer_source_path = root / consumer_source_relative
    consumer_source_path.parent.mkdir(parents=True, exist_ok=True)
    consumer_source_path.write_bytes((source_root / consumer_source_relative).read_bytes())
    (root / target_relative / "src").mkdir(parents=True, exist_ok=True)
    (root / target_relative / "src/lib.rs").write_text("pub struct FailureFingerprint;\n", encoding="utf-8")
    (root / consumer_relative / "src").mkdir(parents=True, exist_ok=True)
    (root / consumer_relative / "src/lib.rs").write_text("mod negative_memory_gate;\n", encoding="utf-8")
    (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")

    decision_lines = [
        f'schema = "{cri.DECISION_SCHEMA}"',
        f'revision = "{registry["revision"]}"',
        "decision = []",
        "",
        f'[[{cri.ADMISSION_DATA_KEY}]]',
        f'package = {json.dumps(record["package"], ensure_ascii=False)}',
    ]
    for field in _I223_ADMISSION_FIELDS:
        decision_lines.append(f"{field} = {json.dumps(record[field], ensure_ascii=False)}")
    decision_lines.append(f'disposition = {json.dumps(record["disposition"])}')
    decision_path = root / cri.DECISION_DATA_RELPATH
    decision_path.parent.mkdir(parents=True, exist_ok=True)
    decision_path.write_text("\n".join(decision_lines) + "\n", encoding="utf-8")

    target_manifest = tomllib.loads((root / target_relative / "Cargo.toml").read_text(encoding="utf-8"))
    consumer_manifest = tomllib.loads((root / consumer_relative / "Cargo.toml").read_text(encoding="utf-8"))
    source_workspace_package = tomllib.loads((source_root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]
    package_rows = [
        {
            "id": target_id,
            "name": package_name,
            "version": target_manifest["package"]["version"],
            "manifest_path": str(root / target_relative / "Cargo.toml"),
            "source": None,
            "metadata": target_manifest["package"].get("metadata", {}),
            "targets": [
                {
                    "name": "eliot_dreamer_failure",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": str(root / target_relative / "src/lib.rs"),
                    "edition": "2024",
                }
            ],
        },
        {
            "id": consumer_id,
            "name": "eliot-governor",
            "version": source_workspace_package["version"],
            "manifest_path": str(root / consumer_relative / "Cargo.toml"),
            "source": None,
            "metadata": consumer_manifest["package"].get("metadata", {}),
            "targets": [
                {
                    "name": "eliot_governor",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": str(root / consumer_relative / "src/lib.rs"),
                    "edition": source_workspace_package["edition"],
                }
            ],
        },
    ]
    metadata = {
        "packages": package_rows,
        "workspace_members": [target_id, consumer_id],
        "workspace_default_members": [target_id, consumer_id],
        "workspace_root": str(root),
        "resolve": {
            "nodes": [
                {"id": target_id, "deps": []},
                {
                    "id": consumer_id,
                    "deps": [
                        {
                            "pkg": target_id,
                            "name": "eliot_dreamer_failure",
                            "dep_kinds": [{"kind": "normal", "target": None}],
                        }
                    ],
                },
            ]
        },
    }
    tracked_manifests = (
        "Cargo.toml",
        f"{target_relative}/Cargo.toml",
        f"{consumer_relative}/Cargo.toml",
    )
    responses = {
        _MANIFESTS_COMMAND: ("\x00".join(tracked_manifests) + "\x00").encode("utf-8"),
        _METADATA_COMMAND: json.dumps(metadata, sort_keys=True).encode("utf-8"),
        ("git", "rev-parse", "HEAD"): (_FIXTURE_HEAD + "\n").encode("ascii"),
        ("git", "status", "--porcelain=v1", "--untracked-files=no"): b"",
        ("cargo", "-Vv"): b"cargo fixture runner (not a toolchain claim)\n",
        ("rustc", "-Vv"): b"rustc fixture runner (not a toolchain claim)\n",
        _MODULES_COMMAND: (module_relative + "\x00").encode("utf-8"),
    }
    return _StrictRunner(responses), {
        "consumer_id": consumer_id,
        "consumer_source_path": consumer_source_path,
        "decision_path": decision_path,
        "module_relative": module_relative,
        "package": package_name,
        "proof_entrypoint": record["public_contract_and_independent_test_entrypoint"].split(";", 1)[0],
        "record": record,
        "registry": registry,
    }


class TestCrateReachabilityInventory(unittest.TestCase):
    def test_self_test_runs_cleanly(self) -> None:
        exit_code = run_self_tests()
        self.assertEqual(exit_code, 0)

    def test_mask_rust_comprehensive(self) -> None:
        source = """
        // comment line
        /* block comment */
        /* nested /* block */ comment */
        fn test<'a, 'de>(val: &'static str) -> bool {
            let ch = 'z';
            let byte_ch = b'x';
            let quote_ch = '"';
            let escaped_single = '\\'';
            let newline_byte = b'\\n';
            let s = "string with \\"quotes\\"";
            let raw = r#"raw "inside" string"#;
            let raw_multi = r##"hashes ##"##;
            todo!("do work");
            unimplemented!();
            unsafe { std::process::Command::new("cargo"); }
            true
        }
        """
        masked = _mask_rust(source)
        self.assertNotIn("// comment line", masked)
        self.assertNotIn("/* block comment */", masked)
        self.assertNotIn("string with", masked)
        self.assertNotIn("raw \"inside\"", masked)
        self.assertNotIn("'z'", masked)
        self.assertNotIn("b'x'", masked)
        self.assertIn("fn test", masked)
        self.assertIn("todo!", masked)
        self.assertIn("unimplemented!", masked)
        self.assertIn("unsafe", masked)
        self.assertIn("Command::new", masked)

    def test_unclosed_block_comment_fails(self) -> None:
        with self.assertRaises(InventoryError) as ctx:
            _mask_rust("/* unclosed comment")
        self.assertEqual(ctx.exception.code, "MALFORMED_RUST_SOURCE")

    def test_unclosed_string_literal_fails(self) -> None:
        with self.assertRaises(InventoryError) as ctx:
            _mask_rust('let s = "unclosed;')
        self.assertEqual(ctx.exception.code, "MALFORMED_RUST_SOURCE")

    def test_unclosed_raw_string_fails(self) -> None:
        with self.assertRaises(InventoryError) as ctx:
            _mask_rust('let s = r#"unclosed;')
        self.assertEqual(ctx.exception.code, "MALFORMED_RUST_SOURCE")

    def test_canonical_bytes_determinism(self) -> None:
        obj1 = {"z": 1, "a": [3, 2, 1], "m": {"b": 2, "a": 1}}
        obj2 = {"a": [3, 2, 1], "m": {"a": 1, "b": 2}, "z": 1}
        self.assertEqual(_canonical_bytes(obj1), _canonical_bytes(obj2))
        self.assertEqual(_sha256(_canonical_bytes(obj1)), _sha256(_canonical_bytes(obj2)))

    def test_safe_output_rejection_outside_eliot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / ".eliot").mkdir()
            with self.assertRaises(InventoryError) as ctx:
                _safe_output(root, root / "forbidden.json")
            self.assertEqual(ctx.exception.code, "UNSAFE_OUTPUT")

    def test_safe_output_existing_refused_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            out_dir = root / ".eliot"
            out_dir.mkdir()
            target = out_dir / "target.json"
            target.write_text("existing", encoding="utf-8")
            with self.assertRaises(InventoryError) as ctx:
                _safe_output(root, target, overwrite=False)
            self.assertEqual(ctx.exception.code, "OUTPUT_EXISTS")

            # Allowed with overwrite=True
            allowed = _safe_output(root, target, overwrite=True)
            self.assertEqual(allowed, target)

    def test_source_file_too_large_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            large_file = root / "large.rs"
            large_file.write_bytes(b"x" * 1024)
            with self.assertRaises(InventoryError) as ctx:
                _read_bytes(root, large_file, max_bytes=512)
            self.assertEqual(ctx.exception.code, "SOURCE_FILE_TOO_LARGE")

    def test_reachability_enumeration_values(self) -> None:
        expected = {
            "BINARY_ENTRYPOINT",
            "PRODUCTION_CONSUMER",
            "BUILD_ONLY",
            "TEST_ONLY",
            "UNRESOLVED_DYNAMIC",
            "NO_CONSUMER",
        }
        actual = {r.value for r in Reachability}
        self.assertEqual(actual, expected)

    def test_manifest_class_enumeration_values(self) -> None:
        expected = {
            "WORKSPACE_ROOT",
            "WORKSPACE_MEMBER",
            "LOCAL_NON_MEMBER_DEPENDENCY",
            "EXCLUDED_PACKAGE",
            "STANDALONE_PACKAGE",
        }
        actual = {m.value for m in ManifestClass}
        self.assertEqual(actual, expected)

    def test_source_scope_values(self) -> None:
        expected = {"PRODUCTION", "BUILD", "TEST", "EXAMPLE", "BENCH", "UNKNOWN"}
        actual = {s.value for s in SourceScope}
        self.assertEqual(actual, expected)

    def test_build_inventory_complete_denominator_and_edge_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))

            self.assertEqual(
                inventory["summary"],
                {
                    "tracked_manifests": 3,
                    "metadata_graphs": 1,
                    "unlocked_metadata_graphs": 0,
                    "packages": 2,
                    "source_files": 2,
                    "findings": 0,
                    "packages_without_consumer": 0,
                    "packages_with_binary_entrypoint": 1,
                    "packages_requiring_review": 0,
                    "complete_denominator": True,
                    "unreachable_classified": 0,
                    "admission_defects": 0,
                    "unclassified_unreachable": 0,
                    "admitted_wave_packages": 0,
                    "admission_wave_defects": 0,
                    "proof_ceiling": "CRATE_REACHABILITY_CLASSIFICATION_AND_SOURCE_SHAPE_EVIDENCE_ONLY",
                },
            )
            self.assertEqual(inventory["workspace_denominator"]["discrepancies"], [])
            self.assertTrue(inventory["workspace_denominator"]["complete"])
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            expected_edges = {
                ("eliot_contracts", "normal", None),
                ("eliot_contracts", "dev", None),
                ("eliot_contracts", "normal", "cfg(windows)"),
            }
            self.assertEqual(
                {
                    (edge["dependency_name"], edge["kind"], edge["target"])
                    for edge in provider["reverse_dependency_edges"]
                },
                expected_edges,
            )
            self.assertEqual(provider["reachability"], "PRODUCTION_CONSUMER")
            self.assertEqual(provider["capability_construction"], "NOWHERE")
            self.assertEqual(provider["source_consumers"], [])
            self.assertEqual(
                provider["support_axes"],
                {
                    "contract_maturity": "SKELETON",
                    "implementation_support": "CURRENT_UNVERIFIED",
                    "evidence_execution_status": "NOT_EXECUTED",
                    "production_reachability": "PRODUCTION_CONSUMER",
                    "runtime_support": "UNKNOWN_FROM_THIS_INVENTORY",
                    "product_support": "UNKNOWN_FROM_THIS_INVENTORY",
                },
            )
            self.assertNotIsInstance(runner, cri.SubprocessRunner)
            self.assertEqual(runner.calls.count(_METADATA_COMMAND), 1)

    def test_workspace_denominator_refuses_a_member_missing_from_root_graph(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertTrue(baseline["workspace_denominator"]["complete"])

            root_metadata = json.loads(runner.responses[_METADATA_COMMAND])
            provider_id = _fixture_id(root, "crates/foundation/eliot-contracts", "eliot-contracts")
            provider_package = next(package for package in root_metadata["packages"] if package["id"] == provider_id)
            root_metadata["packages"] = [package for package in root_metadata["packages"] if package["id"] != provider_id]
            root_metadata["workspace_members"] = [item for item in root_metadata["workspace_members"] if item != provider_id]
            root_metadata["workspace_default_members"] = [
                item for item in root_metadata["workspace_default_members"] if item != provider_id
            ]
            root_metadata["resolve"]["nodes"] = [
                node for node in root_metadata["resolve"]["nodes"] if node["id"] != provider_id
            ]
            for node in root_metadata["resolve"]["nodes"]:
                node["deps"] = [dep for dep in node["deps"] if dep["pkg"] != provider_id]
            runner.responses[_METADATA_COMMAND] = json.dumps(root_metadata, sort_keys=True).encode("utf-8")
            runner.responses[_MEMBER_METADATA_COMMAND] = json.dumps(
                {
                    "packages": [provider_package],
                    "workspace_members": [provider_id],
                    "workspace_default_members": [provider_id],
                    "workspace_root": str(root),
                    "resolve": {"nodes": [{"id": provider_id, "deps": []}]},
                },
                sort_keys=True,
            ).encode("utf-8")
            runner.calls.clear()

            with self.assertRaises(InventoryError) as ctx:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(ctx.exception.code, "INCOMPLETE_DENOMINATOR")
            self.assertEqual(runner.calls.count(_METADATA_COMMAND), 1)
            self.assertEqual(
                sum(command[:2] == ("cargo", "metadata") for command in runner.calls),
                2,
            )

    def test_locked_member_metadata_failure_preserves_runner_created_foreign_lock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertTrue(baseline["workspace_denominator"]["complete"])

            metadata = json.loads(runner.responses[_METADATA_COMMAND])
            provider_id = _fixture_id(root, "crates/foundation/eliot-contracts", "eliot-contracts")
            metadata["packages"] = [package for package in metadata["packages"] if package["id"] != provider_id]
            metadata["workspace_members"] = [item for item in metadata["workspace_members"] if item != provider_id]
            metadata["workspace_default_members"] = [
                item for item in metadata["workspace_default_members"] if item != provider_id
            ]
            metadata["resolve"]["nodes"] = [
                node for node in metadata["resolve"]["nodes"] if node["id"] != provider_id
            ]
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            foreign_lock = b"# created by the injected runner, not by the inventory\n"
            runner.responses[_MEMBER_METADATA_COMMAND] = InventoryError(
                "COMMAND_FAILED",
                "fixture simulates Cargo --locked refusing a lockless standalone package",
            )
            failing_runner = _ForeignLockFailureRunner(
                runner.responses,
                lock_command=_MEMBER_METADATA_COMMAND,
                lock_relative_path="crates/foundation/eliot-contracts/Cargo.lock",
                lock_bytes=foreign_lock,
            )

            with self.assertRaises(InventoryError) as failed:
                build_inventory(root, failing_runner, as_of=date(2026, 9, 29))
            self.assertEqual(failed.exception.code, "COMMAND_FAILED")
            self.assertEqual(failing_runner.calls.count(_MEMBER_METADATA_COMMAND), 1)
            self.assertEqual(
                failing_runner.calls.count(_METADATA_COMMAND),
                1,
                "an incomplete root graph triggers one governed member metadata request",
            )
            self.assertEqual(
                (root / "crates/foundation/eliot-contracts/Cargo.lock").read_bytes(),
                foreign_lock,
            )

    def test_source_construction_requires_production_or_build_code(self) -> None:
        cases = (
            (
                "production",
                {"consumer_source": "fn main() { eliot_contracts::contract(); }\n"},
                "PRODUCTION_CONSTRUCTED",
                "PRODUCTION",
            ),
            (
                "build",
                {
                    "extra_sources": {"bins/eliot/build.rs": "fn build() { eliot_contracts::contract(); }\n"},
                    "dependency_kinds": ({"kind": "build", "target": None},),
                },
                "BUILD_CONSTRUCTED",
                "BUILD",
            ),
        )
        for label, fixture_args, construction, scope in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                runner = _write_inventory_fixture(root, **fixture_args)
                inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
                provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
                self.assertEqual(provider["capability_construction"], construction)
                self.assertEqual(
                    provider["source_consumers"],
                    [{"package_key": next(row["package_key"] for row in inventory["packages"] if row["name"] == "eliot"), "scope": scope}],
                )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(
                root,
                dependency_kinds=({"kind": "dev", "target": None},),
            )
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["reachability"], "TEST_ONLY")
            self.assertEqual(provider["capability_construction"], "NOWHERE")
            self.assertEqual(provider["source_consumers"], [])

    def test_dependency_alias_parameter_shadow_and_qualified_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            consumer_source = root / "bins/eliot/src/main.rs"
            consumer_source.write_text(
                "fn main() { eliot_contracts::contract(); }\n",
                encoding="utf-8",
            )
            positive = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in positive["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["capability_construction"], "PRODUCTION_CONSTRUCTED")

            consumer_source.write_text(
                "use eliot_contracts as provider;\n"
                "fn main() {\n"
                "    fn consume(provider: bool) { let _ = provider; }\n"
                "}\n",
                encoding="utf-8",
            )
            bare_parameter = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in bare_parameter["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["reachability"], "PRODUCTION_CONSUMER")
            self.assertEqual(provider["capability_construction"], "NOWHERE")
            self.assertEqual(provider["source_consumers"], [])

            consumer_source.write_text(
                "use eliot_contracts as provider;\n"
                "fn main() {\n"
                "    fn consume(provider: bool) { let _ = provider::contract(); }\n"
                "}\n",
                encoding="utf-8",
            )
            qualified_parameter = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in qualified_parameter["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["capability_construction"], "PRODUCTION_CONSTRUCTED")
            self.assertEqual(len(provider["source_consumers"]), 1)
            self.assertEqual(provider["source_consumers"][0]["scope"], "PRODUCTION")

            consumer_source.write_text(
                "use eliot_contracts as provider;\n"
                "fn main() {\n"
                "    fn consume(earlier: bool, provider: bool) { let _ = provider::contract(); }\n"
                "}\n",
                encoding="utf-8",
            )
            later_qualified_parameter = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in later_qualified_parameter["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["capability_construction"], "PRODUCTION_CONSTRUCTED")
            self.assertEqual(len(provider["source_consumers"]), 1)

            consumer_source.write_text(
                "fn main() {\n"
                "    fn consume() {\n"
                "        use std as eliot_contracts;\n"
                "        let _ = eliot_contracts::process::id();\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            local_alias = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in local_alias["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["capability_construction"], "NOWHERE")
            self.assertEqual(provider["source_consumers"], [])

    def test_cfg_test_and_external_test_example_bench_consumers_stay_nonproduction(self) -> None:
        cfg_source = (
            "fn main() {}\n"
            "#[cfg(test)]\n"
            "mod tests { fn exercises_contract() { eliot_contracts::contract(); } }\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, consumer_source=cfg_source)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            consumer = next(row for row in inventory["packages"] if row["name"] == "eliot")
            source = next(item for item in inventory["source_files"] if item["path"] == "bins/eliot/src/main.rs")
            self.assertNotIn("eliot_contracts", source["identifiers"])
            self.assertIn("eliot_contracts", source["test_identifiers"])
            self.assertEqual(provider["source_consumers"], [])
            test_consumers = provider["test_only_source_consumers"]
            self.assertEqual(len(test_consumers), 1)
            self.assertEqual(test_consumers[0]["scope"], "PRODUCTION")
            self.assertEqual(test_consumers[0]["context"], "CFG_TEST")
            self.assertEqual(provider["capability_construction"], "TEST_ONLY")
            self.assertEqual(consumer["source_summary"]["production_files"], 1)

        inner_module_source = (
            "fn main() { eliot_contracts::contract(); }\n"
            "mod tests {\n"
            "    #![cfg(test)]\n"
            "    fn exercises_contract() { eliot_contracts::contract(); }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, consumer_source=inner_module_source)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            source = next(item for item in inventory["source_files"] if item["path"] == "bins/eliot/src/main.rs")
            self.assertIn("eliot_contracts", source["identifiers"])
            self.assertIn("eliot_contracts", source["test_identifiers"])
            self.assertEqual(provider["capability_construction"], "PRODUCTION_CONSTRUCTED")
            self.assertEqual({item["scope"] for item in provider["source_consumers"]}, {"PRODUCTION"})
            self.assertEqual(
                {(item["scope"], item["context"]) for item in provider["test_only_source_consumers"]},
                {("PRODUCTION", "CFG_TEST")},
            )

        top_level_inner_source = (
            "#![cfg(test)]\n"
            "fn main() { eliot_contracts::contract(); }\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, consumer_source=top_level_inner_source)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            source = next(item for item in inventory["source_files"] if item["path"] == "bins/eliot/src/main.rs")
            self.assertNotIn("eliot_contracts", source["identifiers"])
            self.assertIn("eliot_contracts", source["test_identifiers"])
            self.assertEqual(provider["capability_construction"], "TEST_ONLY")
            self.assertEqual(provider["source_consumers"], [])

        scoped_sources = {
            "bins/eliot/tests/contract.rs": "use eliot_contracts::contract;\n#[test] fn contract_test() { contract(); }\n",
            "bins/eliot/examples/contract.rs": "fn main() { eliot_contracts::contract(); }\n",
            "bins/eliot/benches/contract.rs": "fn bench() { eliot_contracts::contract(); }\n",
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, extra_sources=scoped_sources)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["source_consumers"], [])
            self.assertEqual(
                {item["scope"] for item in provider["test_only_source_consumers"]},
                {"TEST", "EXAMPLE", "BENCH"},
            )
            self.assertEqual(
                {item["scope"] for item in inventory["source_files"] if item["path"] in scoped_sources},
                {"TEST", "EXAMPLE", "BENCH"},
            )
            self.assertEqual(provider["capability_construction"], "TEST_ONLY")

    def test_utf8_finding_offsets_spans_and_source_digest_use_original_coordinates(self) -> None:
        source = "// café ß placeholder\nfn example(){ todo!(); todo!(); }\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, provider_source=source)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            path = "crates/foundation/eliot-contracts/src/lib.rs"
            marker = next(
                item for item in inventory["findings"]
                if item["path"] == path and item["category"] == "PLACEHOLDER_LANGUAGE"
            )
            code = [
                item for item in inventory["findings"]
                if item["path"] == path and item["category"] == "TODO_MACRO"
            ]
            self.assertEqual(
                (marker["line"], marker["column"], marker["byte_offset"], marker["span"]),
                (1, 11, 12, "placeholder"),
            )
            self.assertEqual(len(code), 2)
            self.assertEqual(
                [(item["line"], item["column"], item["byte_offset"], item["span"]) for item in code],
                [(2, 15, 38, "todo!("), (2, 24, 47, "todo!(")],
            )
            expected_digest = _sha256(source.encode("utf-8"))
            self.assertEqual(marker["source_sha256"], expected_digest)
            self.assertEqual({item["source_sha256"] for item in code}, {expected_digest})
            self.assertEqual(
                len(source.casefold().split("placeholder", 1)[0]),
                11,
                "casefold expands ß before the marker and must not be used as an original offset",
            )

    def test_comment_literal_platform_and_fail_closed_indicator_context(self) -> None:
        source = (
            "// todo!() placeholder\n"
            'fn example() { let marker = "unavailable"; }\n'
            "pub use bridge_contract::*;\n"
            "#[cfg(windows)]\n"
            "pub fn platform_implementation() { todo!(); panic!(); std::process::exit(1); process::exit(78); }\n"
            "#[cfg(not(windows))]\n"
            "pub fn unsupported_platform() { panic!(); }\n"
        )
        source_root = _script_path.resolve().parents[1]
        owner_manifest = source_root / "crates/foundation/eliot-contracts/Cargo.toml"
        owner_manifest_raw = owner_manifest.read_bytes()
        owner_eliot = tomllib.loads(owner_manifest_raw.decode("utf-8"))["package"]["metadata"]["eliot"]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(
                root,
                provider_source=source,
                provider_metadata={"eliot": owner_eliot},
            )
            (root / "crates/foundation/eliot-contracts/Cargo.toml").write_bytes(owner_manifest_raw)
            (root / "crates/AGENTS.md").write_bytes((source_root / "crates/AGENTS.md").read_bytes())
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            path_findings = [item for item in inventory["findings"] if item["path"].endswith("eliot-contracts/src/lib.rs")]
            self.assertFalse(any(item["category"] == "TODO_MACRO" and item["line"] == 1 for item in path_findings))
            text_mentions = [
                item for item in path_findings
                if item["category"] in {"PLACEHOLDER_LANGUAGE", "UNAVAILABLE_ADAPTER_LANGUAGE"}
            ]
            self.assertEqual(len(text_mentions), 2)
            self.assertEqual({item["contextual_disposition"] for item in text_mentions}, {"NON_CODE_MENTION"})
            self.assertEqual(
                {item["contextual_class"] for item in text_mentions},
                {"DOCUMENTATION_OR_LITERAL_MENTION"},
            )
            platform_finding = next(
                item for item in path_findings
                if item["category"] == "TODO_MACRO" and item["line"] == 5
            )
            self.assertEqual(platform_finding["contextual_disposition"], "REVIEW_REQUIRED")
            self.assertIsNone(platform_finding["contextual_class"])
            supported_cfg_panic = next(
                item for item in path_findings
                if item["category"] == "PANIC_MACRO" and item["line"] == 5
            )
            self.assertEqual(supported_cfg_panic["contextual_disposition"], "REVIEW_REQUIRED")
            unsupported_cfg_panic = next(
                item for item in path_findings
                if item["category"] == "PANIC_MACRO" and item["line"] == 7
            )
            self.assertEqual(
                unsupported_cfg_panic["contextual_disposition"],
                "DELIBERATE_UNSUPPORTED_PLATFORM_GUARD",
            )
            self.assertEqual(unsupported_cfg_panic["contextual_class"], "UNSUPPORTED_PLATFORM_GUARD")
            self.assertEqual(
                {item["category"] for item in path_findings if item["line"] == 5},
                {"TODO_MACRO", "PANIC_MACRO", "PROCESS_EXIT", "EXPLICIT_ADMISSION_EXIT"},
            )
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["source_summary"]["public_items"], 3)
            self.assertEqual(
                provider["capability_binding"]["source_maintenance_owner"],
                owner_eliot["source_maintenance_owner"],
            )
            self.assertEqual(provider["support_axes"]["implementation_support"], "CURRENT_UNVERIFIED")
            self.assertEqual(provider["support_axes"]["runtime_support"], "UNKNOWN_FROM_THIS_INVENTORY")
            self.assertEqual(provider["support_axes"]["production_reachability"], provider["reachability"])

    def test_nested_cfg_test_and_inner_attribute_context_precedes_platform_guard(self) -> None:
        source = (
            "#[cfg(not(windows))]\n"
            "mod unsupported {\n"
            "    pub fn unsupported_platform() { panic!(); }\n"
            "    #[cfg(test)]\n"
            "    mod attributed_tests {\n"
            "        fn attributed_fixture() { todo!(); }\n"
            "    }\n"
            "    mod inner_test_scope {\n"
            "        #![cfg(test)]\n"
            "        fn inner_fixture() { todo!(); }\n"
            "    }\n"
            "    // placeholder note\n"
            "}\n"
            "pub fn production_gap() { todo!(); }\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, provider_source=source)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            path = "crates/foundation/eliot-contracts/src/lib.rs"
            source_file = next(item for item in inventory["source_files"] if item["path"] == path)
            self.assertEqual(source_file["scope"], "PRODUCTION")

            findings = [item for item in inventory["findings"] if item["path"] == path]
            test_markers = sorted(
                (item for item in findings if item["category"] == "TODO_MACRO"),
                key=lambda item: item["line"],
            )
            self.assertEqual(
                [
                    (item["line"], item["span"], item["contextual_disposition"], item["contextual_class"])
                    for item in test_markers
                ],
                [
                    (6, "todo!(", "TEST_SCOPE", "TEST_FIXTURE_OR_NON_PRODUCTION_SCOPE"),
                    (10, "todo!(", "TEST_SCOPE", "TEST_FIXTURE_OR_NON_PRODUCTION_SCOPE"),
                    (14, "todo!(", "REVIEW_REQUIRED", None),
                ],
            )
            unsupported_guard = next(
                item for item in findings if item["category"] == "PANIC_MACRO" and item["line"] == 3
            )
            self.assertEqual(
                (unsupported_guard["contextual_disposition"], unsupported_guard["contextual_class"]),
                ("DELIBERATE_UNSUPPORTED_PLATFORM_GUARD", "UNSUPPORTED_PLATFORM_GUARD"),
            )
            comment_finding = next(
                item for item in findings if item["category"] == "PLACEHOLDER_LANGUAGE" and item["line"] == 12
            )
            self.assertEqual(
                (comment_finding["contextual_disposition"], comment_finding["contextual_class"]),
                ("NON_CODE_MENTION", "DOCUMENTATION_OR_LITERAL_MENTION"),
            )

            provider = next(item for item in inventory["packages"] if item["name"] == "eliot-contracts")
            production_fail_closed = provider["production_gap_evidence"]["production_fail_closed_findings"]
            self.assertEqual(
                [
                    (item["path"], item["line"], item["category"], item["span"], item["contextual_disposition"])
                    for item in production_fail_closed
                ],
                [(path, 14, "TODO_MACRO", "todo!(", "REVIEW_REQUIRED")],
            )

    def test_network_filesystem_store_provider_imports_are_contextual_findings_only(self) -> None:
        source = (
            "use std::net::TcpStream;\n"
            "use std::fs::File;\n"
            "use eliot_store_api::Store;\n"
            "use eliot_provider::Provider;\n"
            "fn main() {}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, consumer_source=source)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            imports = [
                item for item in inventory["findings"]
                if item["category"] in {"NETWORK_IMPORT", "FILESYSTEM_IMPORT", "STORE_OR_PROVIDER_IMPORT"}
            ]
            self.assertEqual(
                {item["category"] for item in imports},
                {"NETWORK_IMPORT", "FILESYSTEM_IMPORT", "STORE_OR_PROVIDER_IMPORT"},
            )
            self.assertEqual(
                sum("eliot_store_api::Store" in item["span"] for item in imports),
                1,
            )
            self.assertEqual(
                sum("eliot_provider::Provider" in item["span"] for item in imports),
                1,
            )
            self.assertEqual({item["contextual_disposition"] for item in imports}, {"REVIEW_REQUIRED"})
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["capability_construction"], "NOWHERE")
            self.assertEqual(provider["support_axes"]["implementation_support"], "CURRENT_UNVERIFIED")

    def test_i28_binding_and_nearest_instructions_preserve_declared_owners_only(self) -> None:
        source_root = _script_path.resolve().parents[1]
        manifest_path = source_root / "crates/foundation/eliot-contracts/Cargo.toml"
        manifest_raw = manifest_path.read_bytes()
        manifest = tomllib.loads(manifest_raw.decode("utf-8"))
        eliot = manifest["package"]["metadata"]["eliot"]
        declared_fields = (
            "layer",
            "purpose",
            "source_maintenance_owner",
            "functional_cell_refs",
            "independent_proof_profile",
            "contract_refs",
            "component_contract_ref",
        )
        expected_binding = {field: eliot[field] for field in declared_fields if field in eliot}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, provider_metadata={"eliot": eliot})
            fixture_manifest = root / "crates/foundation/eliot-contracts/Cargo.toml"
            fixture_manifest.write_bytes(manifest_raw)
            actual_instructions = source_root / "crates/AGENTS.md"
            (root / "crates/AGENTS.md").write_bytes(actual_instructions.read_bytes())
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            provider = next(row for row in inventory["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(provider["capability_binding"], expected_binding)
            self.assertEqual(provider["capability_binding"]["functional_cell_refs"], eliot["functional_cell_refs"])
            self.assertEqual(provider["capability_binding"]["contract_refs"], eliot["contract_refs"])
            self.assertEqual(
                provider["capability_binding"]["independent_proof_profile"],
                eliot["independent_proof_profile"],
            )
            self.assertEqual(provider["nearest_instructions"], "crates/AGENTS.md")
            self.assertEqual(provider["owner_issue_refs_from_instructions"], ())
            self.assertEqual(provider["support_axes"]["implementation_support"], "CURRENT_UNVERIFIED")
            self.assertEqual(provider["support_axes"]["contract_maturity"], "SKELETON")
            self.assertEqual(provider["support_axes"]["evidence_execution_status"], "NOT_EXECUTED")

            instructions_path = root / "crates/AGENTS.md"
            original_instructions = instructions_path.read_bytes()
            baseline_instructions_hash = provider["nearest_instructions_sha256"]
            baseline_row_hash = provider["row_sha256"]
            baseline_aggregate = inventory["aggregate_sha256"]
            changed_instructions = original_instructions + b"\n# Ordinary fixture prose, with no new issue references.\n"
            instructions_path.write_bytes(changed_instructions)
            changed = build_inventory(root, runner, as_of=date(2026, 9, 29))
            changed_provider = next(row for row in changed["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(changed_provider["nearest_instructions"], provider["nearest_instructions"])
            self.assertEqual(changed_provider["owner_issue_refs_from_instructions"], ())
            self.assertEqual(changed_provider["nearest_instructions_sha256"], _sha256(changed_instructions))
            self.assertNotEqual(baseline_instructions_hash, changed_provider["nearest_instructions_sha256"])
            self.assertNotEqual(baseline_row_hash, changed_provider["row_sha256"])
            self.assertNotEqual(baseline_aggregate, changed["aggregate_sha256"])

            issue_reference_instructions = original_instructions + b"\n#1720 is a contextual reference only.\n"
            instructions_path.write_bytes(issue_reference_instructions)
            with_issue_reference = build_inventory(root, runner, as_of=date(2026, 9, 29))
            reference_provider = next(row for row in with_issue_reference["packages"] if row["name"] == "eliot-contracts")
            self.assertEqual(reference_provider["owner_issue_refs_from_instructions"], (1720,))
            self.assertEqual(reference_provider["capability_binding"], expected_binding)
            self.assertNotIn("owning_issue_refs", reference_provider["capability_binding"])

    def test_inventory_semantics_are_stable_when_observation_time_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            first = build_inventory(root, runner, as_of=date(2026, 9, 29))
            second = build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(first["summary"], second["summary"])
            self.assertEqual(first["aggregate_sha256"], second["aggregate_sha256"])
            self.assertEqual(
                _canonical_bytes({key: value for key, value in first.items() if key != "observation"}),
                _canonical_bytes({key: value for key, value in second.items() if key != "observation"}),
            )
            self.assertIn("duration_ms", first["observation"])
            stable = {key: value for key, value in first.items() if key not in {"aggregate_sha256", "observation"}}
            self.assertEqual(first["aggregate_sha256"], _sha256(_canonical_bytes(stable)))

    def test_manifest_lock_and_decision_bytes_invalidate_the_bound_digest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            original = build_inventory(root, runner, as_of=date(2026, 9, 29))
            original_rows = {row["name"]: row["row_sha256"] for row in original["packages"]}
            original_summary = dict(original["summary"])

            manifest = root / "bins/eliot/Cargo.toml"
            manifest_bytes = manifest.read_bytes()
            manifest.write_bytes(manifest_bytes + b"\n# fixture input digest change\n")
            changed_manifest = build_inventory(root, runner, as_of=date(2026, 9, 29))
            manifest_row_before = next(row for row in original["manifest_rows"] if row["manifest_path"] == "bins/eliot/Cargo.toml")
            manifest_row_after = next(row for row in changed_manifest["manifest_rows"] if row["manifest_path"] == "bins/eliot/Cargo.toml")
            self.assertNotEqual(manifest_row_before["sha256"], manifest_row_after["sha256"])
            self.assertEqual(original_summary, changed_manifest["summary"])
            self.assertEqual(original_rows, {row["name"]: row["row_sha256"] for row in changed_manifest["packages"]})
            self.assertNotEqual(original["aggregate_sha256"], changed_manifest["aggregate_sha256"])
            manifest.write_bytes(manifest_bytes)

            lock = root / "Cargo.lock"
            lock_bytes = lock.read_bytes()
            lock.write_bytes(lock_bytes + b"# fixture lock digest change\n")
            changed_lock = build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertNotEqual(
                original["source_identity"]["cargo_lock_sha256"],
                changed_lock["source_identity"]["cargo_lock_sha256"],
            )
            self.assertEqual(original_summary, changed_lock["summary"])
            self.assertEqual(original_rows, {row["name"]: row["row_sha256"] for row in changed_lock["packages"]})
            self.assertNotEqual(original["aggregate_sha256"], changed_lock["aggregate_sha256"])
            lock.write_bytes(lock_bytes)

            decisions = root / cri.DECISION_DATA_RELPATH
            decisions_bytes = decisions.read_bytes()
            decisions.write_bytes(decisions_bytes + b"\n# fixture decision digest change\n")
            changed_decisions = build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertNotEqual(
                original["extraction_classification"]["decision_data_sha256"],
                changed_decisions["extraction_classification"]["decision_data_sha256"],
            )
            self.assertEqual(original_summary, changed_decisions["summary"])
            self.assertEqual(original_rows, {row["name"]: row["row_sha256"] for row in changed_decisions["packages"]})
            self.assertNotEqual(original["aggregate_sha256"], changed_decisions["aggregate_sha256"])
            decisions.write_bytes(decisions_bytes)

    def test_canonical_extraction_dispositions_expiry_unclassified_and_orphan(self) -> None:
        source_root = _script_path.resolve().parents[1]
        registry_path = source_root / cri.DECISION_DATA_RELPATH
        registry_raw = registry_path.read_bytes()
        registry = tomllib.loads(registry_raw.decode("utf-8"))
        _, _, records = cri.load_decision_records(registry, _sha256(registry_raw))
        by_disposition = {record.disposition: record for record in records}
        connect = by_disposition[cri.CrateExtractionDecision.CONNECT]
        contract_only = by_disposition[cri.CrateExtractionDecision.CONTRACT_ONLY]
        facade = by_disposition[cri.CrateExtractionDecision.MIGRATION_FACADE]

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".git").mkdir()
            (root / "Cargo.toml").write_text('[workspace]\nmembers = []\nexclude = []\n', encoding="utf-8")
            package_rows: dict[str, dict[str, object]] = {}
            for record in (connect, contract_only, facade):
                package_rows[record.package] = {
                    "package_key": record.package,
                    "name": record.package,
                    "manifest_path": f"crates/{record.package}/Cargo.toml",
                    "workspace_member": True,
                    "workspace_default_member": False,
                    "source": None,
                    "reachability": "NO_CONSUMER",
                    "capability_construction": "NOWHERE",
                    "source_consumers": [],
                }
                for promised_name in (record.declared_consumer, record.declared_bundle):
                    if promised_name and promised_name not in package_rows:
                        package_rows[promised_name] = {
                            "package_key": promised_name,
                            "name": promised_name,
                            "manifest_path": f"crates/{promised_name}/Cargo.toml",
                            "workspace_member": False,
                            "workspace_default_member": False,
                            "source": None,
                            "reachability": "NO_CONSUMER",
                            "capability_construction": "NOWHERE",
                            "source_consumers": [],
                        }
            source_root = _script_path.resolve().parents[1]
            actual_admission = next(
                item for item in registry[cri.ADMISSION_DATA_KEY]
                if item["package"] == "eliot-dreamer-failure"
            )
            optional_package = actual_admission["package"]
            optional_relative = "crates/smart/eliot-dreamer-failure"
            optional_manifest = source_root / optional_relative / "Cargo.toml"
            actual_proof = actual_admission["public_contract_and_independent_test_entrypoint"].split(";", 1)[0]
            proof_path, proof_symbol = actual_proof.split("::", 1)
            (root / optional_relative).mkdir(parents=True, exist_ok=True)
            (root / optional_relative / "Cargo.toml").write_bytes(optional_manifest.read_bytes())
            (root / proof_path).parent.mkdir(parents=True, exist_ok=True)
            (root / proof_path).write_bytes((source_root / proof_path).read_bytes())
            contour = actual_admission["proposed_package_boundary"].partition(" :: ")[0]
            (root / "Cargo.toml").write_text(
                f'[workspace]\nmembers = ["{optional_relative}"]\nexclude = []\n',
                encoding="utf-8",
            )
            # The canonical #1721 record supplies real package, contour, and proof
            # identities; the local record exercises the fourth #1720 branch without
            # adding or claiming an owner-published OptionalContour policy row.
            optional_record = cri.DecisionRecord(
                package=optional_package,
                disposition=cri.CrateExtractionDecision.OPTIONAL_CONTOUR,
                rationale=actual_admission["counter_risks_merge_or_rejoin_condition"],
                owner=None,
                expires=None,
                successor=None,
                removal_condition=None,
                declared_consumer=None,
                declared_bundle=None,
                declared_contour=contour,
                contour_excluded_from_default_path=True,
                proof_entrypoint=actual_proof,
                review_owner=actual_admission["evidence_status_and_review_owner"],
                source_ref=actual_proof,
            )
            package_rows[optional_package] = {
                "package_key": optional_package,
                "name": optional_package,
                "manifest_path": f"{optional_relative}/Cargo.toml",
                "workspace_member": True,
                "workspace_default_member": False,
                "source": None,
                "reachability": "NO_CONSUMER",
                "capability_construction": "NOWHERE",
                "source_consumers": [],
            }
            classifications, defects, _ = cri.classify_unreachable_packages(
                root,
                list(package_rows.values()),
                (connect, contract_only, facade, optional_record),
                as_of=date(2026, 9, 29),
            )
            by_package = {item["package"]: item for item in classifications}
            self.assertEqual(by_package[connect.package]["classification"], "Connect")
            self.assertTrue(by_package[connect.package]["admitted"])
            self.assertEqual(by_package[contract_only.package]["classification"], "ContractOnly")
            self.assertTrue(by_package[contract_only.package]["admitted"])
            self.assertEqual(by_package[facade.package]["classification"], "MigrationFacade")
            self.assertTrue(by_package[facade.package]["admitted"])
            self.assertEqual(by_package[facade.package]["record"], facade.to_json())
            self.assertEqual(
                by_package[facade.package]["record"]["declared_consumer"],
                facade.declared_consumer,
            )
            self.assertEqual(by_package[optional_package]["classification"], "OptionalContour")
            self.assertTrue(by_package[optional_package]["admitted"])
            self.assertEqual(defects, [])

            expired_after_declared_date = date.fromisoformat(facade.expires) + timedelta(days=1)
            expired, expired_defects, _ = cri.classify_unreachable_packages(
                root, [package_rows[facade.package]], [facade], as_of=expired_after_declared_date
            )
            self.assertIn("FACADE_EXPIRED", expired[0]["defects"])
            self.assertEqual(expired_defects[0]["defects"], ["FACADE_EXPIRED"])

            unclassified, unclassified_defects, _ = cri.classify_unreachable_packages(
                root, [package_rows[connect.package]], [], as_of=date(2026, 9, 29)
            )
            self.assertEqual(unclassified[0]["defects"], ["UNCLASSIFIED"])
            self.assertEqual(unclassified_defects[0]["defects"], ["UNCLASSIFIED"])

            optional_contour = dataclasses.replace(
                optional_record,
                declared_contour=None,
                proof_entrypoint=None,
                contour_excluded_from_default_path=None,
            )
            optional, optional_defects, _ = cri.classify_unreachable_packages(
                root,
                [package_rows[optional_package]],
                [optional_contour],
                as_of=date(2026, 9, 29),
            )
            self.assertEqual(optional[0]["classification"], "OptionalContour")
            self.assertEqual(
                optional[0]["defects"],
                ["DECLARED_CONTOUR_ABSENT", "DECLARED_ENTRYPOINT_ABSENT"],
            )
            self.assertEqual(optional_defects[0]["defects"], optional[0]["defects"])

            orphan = next(record for record in records if record.package not in package_rows)
            _, _, orphan_rows = cri.classify_unreachable_packages(
                root, [package_rows[connect.package]], [connect, orphan], as_of=date(2026, 9, 29)
            )
            self.assertEqual(
                orphan_rows,
                [{
                    "package": orphan.package,
                    "disposition": orphan.disposition.value,
                    "defect": "DECISION_FOR_UNKNOWN_PACKAGE",
                }],
            )

    def test_i223_metadata_record_shape_and_path_symbol_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner, fixture = _canonical_supplier_fixture(root)
            baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
            classification = next(
                row for row in baseline["capability_admission"]["classifications"]
                if row["package"] == fixture["package"]
            )
            self.assertTrue(classification["admitted"])
            self.assertEqual(classification["defects"], [])
            self.assertEqual(cri.ADMISSION_FIELDS, _I223_ADMISSION_FIELDS)
            expected_record_keys = {"package", "disposition", *_I223_ADMISSION_FIELDS}
            self.assertEqual(set(classification["record"]), expected_record_keys)
            self.assertEqual(set(fixture["record"]) - {"package", "disposition"}, set(_I223_ADMISSION_FIELDS))

            decision_path = fixture["decision_path"]
            original = decision_path.read_text(encoding="utf-8")
            proof_reference = fixture["proof_entrypoint"]
            proof_path_only = proof_reference.split("::", 1)[0]
            self.assertIn(proof_reference, original)
            decision_path.write_text(original.replace(proof_reference, proof_path_only, 1), encoding="utf-8")
            refused = build_inventory(root, runner, as_of=date(2026, 9, 29))
            refused_classification = next(
                row for row in refused["capability_admission"]["classifications"]
                if row["package"] == fixture["package"]
            )
            self.assertIn("ADMISSION_ENTRYPOINT_ABSENT", refused_classification["defects"])

            decision_path.write_text(original, encoding="utf-8")
            proof_path, proof_symbol = proof_reference.split("::", 1)
            proof_file = root / proof_path
            original_proof = proof_file.read_bytes()
            proof_file.write_text(
                f'// fn {proof_symbol}() {{}}\n'
                f'const CLAIM: &str = "fn {proof_symbol}() {{}}";\n',
                encoding="utf-8",
            )
            comment_only_proof = build_inventory(root, runner, as_of=date(2026, 9, 29))
            comment_only_classification = next(
                row for row in comment_only_proof["capability_admission"]["classifications"]
                if row["package"] == fixture["package"]
            )
            self.assertIn("ADMISSION_ENTRYPOINT_ABSENT", comment_only_classification["defects"])
            proof_file.write_bytes(original_proof)

    def test_actual_admission_record_outside_module_denominator_is_an_orphan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner, fixture = _canonical_supplier_fixture(root)
            baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
            baseline_row = next(
                row for row in baseline["capability_admission"]["classifications"]
                if row["package"] == fixture["package"]
            )
            self.assertTrue(baseline_row["admitted"])

            runner.responses[_MODULES_COMMAND] = b""
            orphaned = build_inventory(root, runner, as_of=date(2026, 9, 29))
            orphan = next(
                row for row in orphaned["capability_admission"]["classifications"]
                if row["package"] == fixture["package"]
            )
            self.assertFalse(orphan["admitted"])
            self.assertEqual(orphan["defects"], ["ADMISSION_RECORD_FOR_UNKNOWN_PACKAGE"])
            self.assertEqual(set(orphan["record"]), {"package", "disposition", *_I223_ADMISSION_FIELDS})
            orphan_defect = next(
                row for row in orphaned["capability_admission"]["admission_defects"]
                if row["package"] == fixture["package"]
            )
            self.assertEqual(orphan_defect["defects"], ["ADMISSION_RECORD_FOR_UNKNOWN_PACKAGE"])

    def test_malformed_manifest_metadata_source_and_decision_data_refuse_after_valid_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertTrue(baseline["workspace_denominator"]["complete"])

            source_path = root / "crates/foundation/eliot-contracts/src/lib.rs"
            source_bytes = source_path.read_bytes()
            source_path.write_bytes(b"/* unterminated")
            with self.assertRaises(InventoryError) as malformed_source:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(malformed_source.exception.code, "MALFORMED_RUST_SOURCE")
            source_path.write_bytes(source_bytes)

            invalid_utf8_path = root / "bins/eliot/src/main.rs"
            valid_source = invalid_utf8_path.read_bytes()
            invalid_utf8_path.write_bytes(b"\xff")
            with self.assertRaises(InventoryError) as invalid_utf8:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(invalid_utf8.exception.code, "INVALID_RUST_ENCODING")
            invalid_utf8_path.write_bytes(valid_source)

            root_manifest = root / "Cargo.toml"
            valid_manifest = root_manifest.read_bytes()
            root_manifest.write_text('[workspace]\nmembers = [\n', encoding="utf-8")
            with self.assertRaises(InventoryError) as malformed_manifest:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(malformed_manifest.exception.code, "MALFORMED_MANIFEST")
            root_manifest.write_bytes(valid_manifest)

            original_metadata = runner.responses[_METADATA_COMMAND]
            with tempfile.TemporaryDirectory() as foreign_td:
                foreign_root = Path(foreign_td)

                malformed_metadata_cases = (
                    (
                        "blank_workspace_root",
                        lambda metadata: metadata.__setitem__("workspace_root", ""),
                        "MALFORMED_METADATA",
                    ),
                    (
                        "relative_workspace_root",
                        lambda metadata: metadata.__setitem__("workspace_root", "relative/root"),
                        "MALFORMED_METADATA",
                    ),
                    (
                        "wrong_existing_workspace_root",
                        lambda metadata: metadata.__setitem__("workspace_root", str(root / "bins/eliot")),
                        "MALFORMED_METADATA",
                    ),
                    (
                        "workspace_root_outside_repository",
                        lambda metadata: metadata.__setitem__("workspace_root", str(foreign_root)),
                        "PATH_ESCAPE",
                    ),
                    (
                        "target_path_outside_repository",
                        lambda metadata: metadata["packages"][1]["targets"][0].__setitem__(
                            "src_path", str(root.parent / "outside.rs")
                        ),
                        "PATH_ESCAPE",
                    ),
                    (
                        "duplicate_workspace_member",
                        lambda metadata: metadata["workspace_members"].append(metadata["workspace_members"][0]),
                        "MALFORMED_METADATA",
                    ),
                    (
                        "duplicate_default_member",
                        lambda metadata: metadata["workspace_default_members"].append(
                            metadata["workspace_default_members"][0]
                        ),
                        "MALFORMED_METADATA",
                    ),
                    (
                        "empty_local_package_targets",
                        lambda metadata: metadata["packages"][1].__setitem__("targets", []),
                        "MALFORMED_METADATA",
                    ),
                )
                for label, mutate, expected_code in malformed_metadata_cases:
                    with self.subTest(metadata_shape=label):
                        malformed = json.loads(original_metadata)
                        mutate(malformed)
                        runner.responses[_METADATA_COMMAND] = json.dumps(malformed, sort_keys=True).encode("utf-8")
                        with self.assertRaises(InventoryError) as refusal:
                            build_inventory(root, runner, as_of=date(2026, 9, 29))
                        self.assertEqual(refusal.exception.code, expected_code)

            runner.responses[_METADATA_COMMAND] = original_metadata
            metadata = json.loads(original_metadata)
            metadata["resolve"] = None
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as malformed_resolve:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(malformed_resolve.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            provider_target = metadata["packages"][1]["targets"][0]
            provider_target["src_path"] = "relative/path.rs"
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as malformed_target:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(malformed_target.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            dependency_node = metadata["resolve"]["nodes"][0]
            dependency_node["deps"][0]["dep_kinds"] = []
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as unresolved_kinds:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(unresolved_kinds.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            metadata["packages"][1]["id"] = ""
            metadata["resolve"]["nodes"][1]["id"] = ""
            metadata["resolve"]["nodes"][0]["deps"][0]["pkg"] = ""
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as empty_package_identity:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(empty_package_identity.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            metadata["resolve"]["nodes"][0]["deps"][0]["pkg"] = ""
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as empty_dependency_identity:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(empty_dependency_identity.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["kind"] = "foreign-kind"
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as unknown_kind:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(unknown_kind.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["target"] = ""
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as empty_dependency_target:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(empty_dependency_target.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["target"] = {"os": "windows"}
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as malformed_target_cfg:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(malformed_target_cfg.exception.code, "MALFORMED_METADATA")
            runner.responses[_METADATA_COMMAND] = original_metadata

            metadata = json.loads(original_metadata)
            metadata["packages"].append("not a Cargo package object")
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as non_object_package:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(non_object_package.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            provider_target = metadata["packages"][1]["targets"][0]
            metadata["packages"][1]["targets"].append(dict(provider_target))
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as duplicate_target:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(duplicate_target.exception.code, "MALFORMED_METADATA")

            metadata = json.loads(original_metadata)
            package_relative_target = root / "bins/eliot/generated.rs"
            package_relative_target.write_text("", encoding="utf-8")
            metadata["packages"][0]["targets"][0]["src_path"] = str(package_relative_target)
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            with self.assertRaises(InventoryError) as unscanned_target:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(unscanned_target.exception.code, "MALFORMED_METADATA")
            runner.responses[_METADATA_COMMAND] = original_metadata

            decision_path = root / cri.DECISION_DATA_RELPATH
            valid_decisions = decision_path.read_bytes()
            decision_path.write_text('schema = "unrecognized"\nrevision = "2026-09-29.1"\ndecision = []\n', encoding="utf-8")
            with self.assertRaises(InventoryError) as malformed_decisions:
                build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertEqual(malformed_decisions.exception.code, "MALFORMED_DECISION_DATA")
            decision_path.write_bytes(valid_decisions)

    def test_toolchain_source_and_owner_metadata_changes_invalidate_bound_rows(self) -> None:
        source_root = _script_path.resolve().parents[1]
        manifest_path = source_root / "crates/foundation/eliot-contracts/Cargo.toml"
        manifest_bytes = manifest_path.read_bytes()
        metadata_eliot = tomllib.loads(manifest_bytes.decode("utf-8"))["package"]["metadata"]["eliot"]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, provider_metadata={"eliot": metadata_eliot})
            (root / "crates/foundation/eliot-contracts/Cargo.toml").write_bytes(manifest_bytes)
            baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
            baseline_provider = next(row for row in baseline["packages"] if row["name"] == "eliot-contracts")

            source_path = root / "crates/foundation/eliot-contracts/src/lib.rs"
            source_path.write_bytes(source_path.read_bytes() + b"// source digest input\n")
            changed_source = build_inventory(root, runner, as_of=date(2026, 9, 29))
            changed_provider = next(row for row in changed_source["packages"] if row["name"] == "eliot-contracts")
            source_evidence_before = next(item for item in baseline["source_files"] if item["path"].endswith("eliot-contracts/src/lib.rs"))
            source_evidence_after = next(item for item in changed_source["source_files"] if item["path"].endswith("eliot-contracts/src/lib.rs"))
            self.assertNotEqual(source_evidence_before["sha256"], source_evidence_after["sha256"])
            self.assertNotEqual(baseline_provider["row_sha256"], changed_provider["row_sha256"])
            self.assertNotEqual(baseline["aggregate_sha256"], changed_source["aggregate_sha256"])

            runner.responses[("cargo", "-Vv")] = b"cargo fixture runner changed fingerprint\n"
            changed_toolchain = build_inventory(root, runner, as_of=date(2026, 9, 29))
            changed_toolchain_provider = next(row for row in changed_toolchain["packages"] if row["name"] == "eliot-contracts")
            self.assertNotEqual(
                changed_source["source_identity"]["cargo_version"],
                changed_toolchain["source_identity"]["cargo_version"],
            )
            self.assertEqual(changed_provider["row_sha256"], changed_toolchain_provider["row_sha256"])
            self.assertNotEqual(changed_source["aggregate_sha256"], changed_toolchain["aggregate_sha256"])

            owner_manifest = root / "crates/foundation/eliot-contracts/Cargo.toml"
            owner_manifest_raw = owner_manifest.read_text(encoding="utf-8")
            owner_line = f'source_maintenance_owner = "{metadata_eliot["source_maintenance_owner"]}"\n'
            self.assertIn(owner_line, owner_manifest_raw)
            owner_manifest.write_text(owner_manifest_raw.replace(owner_line, "", 1), encoding="utf-8")
            metadata = json.loads(runner.responses[_METADATA_COMMAND])
            provider_package = next(package for package in metadata["packages"] if package["name"] == "eliot-contracts")
            del provider_package["metadata"]["eliot"]["source_maintenance_owner"]
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            changed_owner = build_inventory(root, runner, as_of=date(2026, 9, 29))
            changed_owner_provider = next(row for row in changed_owner["packages"] if row["name"] == "eliot-contracts")
            self.assertNotIn("source_maintenance_owner", changed_owner_provider["capability_binding"])
            self.assertNotIn("owner_status", changed_owner_provider["capability_binding"])
            self.assertNotEqual(changed_toolchain_provider["row_sha256"], changed_owner_provider["row_sha256"])
            self.assertNotEqual(changed_toolchain["aggregate_sha256"], changed_owner["aggregate_sha256"])

    def test_actual_named_consumer_requires_source_bound_supplier_use_and_normal_edge(self) -> None:
        scenarios = (
            "empty",
            "unrelated",
            "cfg_test",
            "dev_edge",
            "sibling_module_alias",
            "local_item_shadows_import",
            "local_root_alias",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                runner, fixture = _canonical_supplier_fixture(root)
                baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
                valid = next(
                    row for row in baseline["capability_admission"]["classifications"]
                    if row["package"] == fixture["package"]
                )
                self.assertTrue(valid["admitted"], "actual declared source pair must establish the fixture baseline")

                if scenario == "empty":
                    fixture["consumer_source_path"].write_text(
                        "pub fn evaluate_negative_memory_gate() {}\n",
                        encoding="utf-8",
                    )
                elif scenario == "unrelated":
                    fixture["consumer_source_path"].write_text(
                        "pub fn evaluate_negative_memory_gate() {}\n"
                        "fn unrelated_sibling() { let _: Option<eliot_dreamer_failure::ExactMatch> = None; }\n",
                        encoding="utf-8",
                    )
                elif scenario == "cfg_test":
                    fixture["consumer_source_path"].write_text(
                        "#[cfg(test)]\n"
                        "pub fn evaluate_negative_memory_gate() { let _: Option<eliot_dreamer_failure::ExactMatch> = None; }\n",
                        encoding="utf-8",
                    )
                elif scenario == "dev_edge":
                    metadata = json.loads(runner.responses[_METADATA_COMMAND])
                    consumer_node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == fixture["consumer_id"])
                    consumer_node["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
                    runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
                elif scenario == "sibling_module_alias":
                    fixture["consumer_source_path"].write_text(
                        "mod match_negative_memory { pub struct NegativeMemoryMatchResult; }\n"
                        "mod sibling { use eliot_dreamer_failure as match_negative_memory; }\n"
                        "pub fn evaluate_negative_memory_gate() {\n"
                        "    let _: Option<match_negative_memory::NegativeMemoryMatchResult> = None;\n"
                        "}\n",
                        encoding="utf-8",
                    )
                elif scenario == "local_item_shadows_import":
                    fixture["consumer_source_path"].write_text(
                        "use eliot_dreamer_failure::match_negative_memory;\n"
                        "pub fn evaluate_negative_memory_gate() {\n"
                        "    fn match_negative_memory() {}\n"
                        "    match_negative_memory();\n"
                        "}\n",
                        encoding="utf-8",
                    )
                else:
                    fixture["consumer_source_path"].write_text(
                        "use crate::composition as eliot_dreamer_failure;\n"
                        "pub fn evaluate_negative_memory_gate() {\n"
                        "    let _: Option<eliot_dreamer_failure::NegativeMemoryMatchResult> = None;\n"
                        "}\n",
                        encoding="utf-8",
                    )

                refused = build_inventory(root, runner, as_of=date(2026, 9, 29))
                refused_classification = next(
                    row for row in refused["capability_admission"]["classifications"]
                    if row["package"] == fixture["package"]
                )
                self.assertFalse(refused_classification["admitted"])
                self.assertIn("ADMISSION_CONSUMER_ABSENT", refused_classification["defects"])

    def test_admission_reconciliation_joins_supplier_classification_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner, fixture = _canonical_supplier_fixture(root)
            baseline = build_inventory(root, runner, as_of=date(2026, 9, 29))
            self.assertTrue(
                next(row for row in baseline["capability_admission"]["classifications"] if row["package"] == fixture["package"])["admitted"]
            )

            metadata = json.loads(runner.responses[_METADATA_COMMAND])
            consumer_node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == fixture["consumer_id"])
            consumer_node["deps"] = []
            runner.responses[_METADATA_COMMAND] = json.dumps(metadata, sort_keys=True).encode("utf-8")
            defective = build_inventory(root, runner, as_of=date(2026, 9, 29))
            classification = next(
                row for row in defective["capability_admission"]["classifications"]
                if row["package"] == fixture["package"]
            )
            defect = next(
                row for row in defective["capability_admission"]["admission_defects"]
                if row["package"] == fixture["package"]
            )
            self.assertIn("evidence_status_and_review_owner", classification["record"])
            self.assertNotIn("record", defect)
            self.assertIn("ADMISSION_CONSUMER_ABSENT", defect["defects"])

            gaps = cri.reconciliation_map(defective)
            self.assertEqual(len(gaps), 3)
            self.assertEqual(
                {(gap["package"], gap["layer"]) for gap in gaps},
                {("eliot-governor", "1720"), (fixture["package"], "1720"), (fixture["package"], "1721")},
            )
            admission_gap = next(gap for gap in gaps if gap["layer"] == "1721")
            self.assertEqual(admission_gap["package"], fixture["package"])
            self.assertEqual(admission_gap["owner"], classification["record"]["evidence_status_and_review_owner"])
            self.assertTrue(admission_gap["gap"].startswith("ADMISSION_DEFECT: "))
            for gap in gaps:
                self.assertIsInstance(gap["owner"], str)
                self.assertTrue(gap["owner"])
                self.assertTrue(gap["bounded_issue"]["title"].startswith("[1720-reconcile] "))
                self.assertIn("acceptance", gap["bounded_issue"])
                if gap["layer"] == "1720":
                    self.assertEqual(gap["owner"], cri.ISSUE_1720_OWNER)
                    self.assertEqual(gap["gap"], "UNCLASSIFIED: no decision row")

    def test_reconciliation_fallback_and_orphan_are_single_bounded_gaps(self) -> None:
        source_root = _script_path.resolve().parents[1]
        registry = tomllib.loads((source_root / cri.DECISION_DATA_RELPATH).read_text(encoding="utf-8"))
        raw_records = registry["decision"]
        orphan_package = next(
            item["package"] for item in raw_records if item["package"] != "eliot-dreamer-accessibility"
        )
        missing_package = "eliot-dreamer-accessibility"
        orphan_inventory = {
            "extraction_classification": {
                "classifications": [],
                "admission_defects": [],
                "orphan_decisions": [{
                    "package": orphan_package,
                    "disposition": next(item["disposition"] for item in raw_records if item["package"] == orphan_package),
                    "defect": "DECISION_FOR_UNKNOWN_PACKAGE",
                }],
            },
            "capability_admission": {"classifications": [], "admission_defects": []},
        }
        orphan_gaps = cri.reconciliation_map(orphan_inventory)
        self.assertEqual(len(orphan_gaps), 1)
        self.assertEqual(orphan_gaps[0]["owner"], cri.ISSUE_1720_OWNER)
        self.assertTrue(orphan_gaps[0]["gap"].startswith("ORPHAN_ROW: "))

        missing_record_inventory = {
            "extraction_classification": {
                "classifications": [{"package": missing_package, "classification": None, "record": None}],
                "admission_defects": [{"package": missing_package, "defects": ["UNCLASSIFIED"]}],
                "orphan_decisions": [],
            },
            "capability_admission": {"classifications": [], "admission_defects": []},
        }
        missing_gaps = cri.reconciliation_map(missing_record_inventory)
        self.assertEqual(len(missing_gaps), 1)
        self.assertEqual(missing_gaps[0]["owner"], cri.ISSUE_1720_OWNER)
        self.assertTrue(missing_gaps[0]["gap"].startswith("UNCLASSIFIED: "))

    def test_cli_writes_only_eliot_inventory_and_reconcile_outputs_and_reports_errors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root)
            inventory = build_inventory(root, runner, as_of=date(2026, 9, 29))
            output_path = root / ".eliot/crate-reachability.json"
            reconcile_path = root / ".eliot/reconciliation.json"
            second_output_path = root / ".eliot/crate-reachability-second.json"
            second_reconcile_path = root / ".eliot/reconciliation-second.json"
            stdout = io.StringIO()
            with mock.patch.object(cri, "build_inventory", return_value=inventory), mock.patch("sys.stdout", stdout):
                exit_code = cri.main([
                    "--repo-root", str(root),
                    "--output", ".eliot/crate-reachability.json",
                    "--reconcile", ".eliot/reconciliation.json",
                    "--as-of", "2026-09-29",
                ])
            self.assertEqual(exit_code, 0)
            self.assertEqual(output_path.read_bytes(), _canonical_bytes(inventory) + b"\n")
            self.assertEqual(
                json.loads(reconcile_path.read_text(encoding="utf-8")),
                {"gaps": []},
            )
            self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")
            self.assertEqual(output_path.parent, root / ".eliot")
            self.assertEqual(reconcile_path.parent, root / ".eliot")

            second_stdout = io.StringIO()
            with mock.patch.object(cri, "build_inventory", return_value=inventory), mock.patch("sys.stdout", second_stdout):
                second_exit_code = cri.main([
                    "--repo-root", str(root),
                    "--output", ".eliot/crate-reachability-second.json",
                    "--reconcile", ".eliot/reconciliation-second.json",
                    "--as-of", "2026-09-29",
                ])
            self.assertEqual(second_exit_code, 0)
            verification = json.loads(stdout.getvalue())
            second_verification = json.loads(second_stdout.getvalue())
            self.assertEqual(verification["aggregate_sha256"], inventory["aggregate_sha256"])
            self.assertEqual(second_verification["aggregate_sha256"], verification["aggregate_sha256"])
            self.assertEqual(output_path.read_bytes(), second_output_path.read_bytes())
            self.assertEqual(reconcile_path.read_bytes(), second_reconcile_path.read_bytes())
            self.assertEqual(second_output_path.parent, root / ".eliot")
            self.assertEqual(second_reconcile_path.parent, root / ".eliot")

            error_stdout = io.StringIO()
            error_stderr = io.StringIO()
            with mock.patch.object(cri, "build_inventory") as builder, \
                    mock.patch("sys.stdout", error_stdout), mock.patch("sys.stderr", error_stderr):
                error_code = cri.main([
                    "--repo-root", str(root),
                    "--output", ".eliot/invalid-date.json",
                    "--as-of", "2026-9-29",
                ])
            self.assertEqual(error_code, 2)
            builder.assert_not_called()
            self.assertEqual(error_stdout.getvalue(), "")
            self.assertEqual(json.loads(error_stderr.getvalue())["status"], "error")
            self.assertFalse((root / ".eliot/invalid-date.json").exists())

            malformed_source_stdout = io.StringIO()
            malformed_source_stderr = io.StringIO()
            with mock.patch.object(
                cri,
                "build_inventory",
                side_effect=InventoryError("MALFORMED_RUST_SOURCE", "unterminated block comment"),
            ), mock.patch("sys.stdout", malformed_source_stdout), mock.patch("sys.stderr", malformed_source_stderr):
                malformed_source_exit = cri.main([
                    "--repo-root", str(root),
                    "--output", ".eliot/malformed-source.json",
                    "--as-of", "2026-09-29",
                ])
            self.assertEqual(malformed_source_exit, 2)
            self.assertEqual(malformed_source_stdout.getvalue(), "")
            self.assertEqual(
                json.loads(malformed_source_stderr.getvalue()),
                {
                    "status": "error",
                    "code": "MALFORMED_RUST_SOURCE",
                    "detail": "unterminated block comment",
                },
            )
            self.assertFalse((root / ".eliot/malformed-source.json").exists())

    def test_cli_refuses_unavailable_pinned_member_dependency(self) -> None:
        detail = "offline cache lacks pinned serde 1.0.228; only serde 1.0.229 is available"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = _write_inventory_fixture(root, metadata_omits_provider=True)
            runner.responses[_MEMBER_METADATA_COMMAND] = InventoryError("COMMAND_FAILED", detail)
            stdout = io.StringIO()
            stderr = io.StringIO()

            with mock.patch.object(cri, "SubprocessRunner", return_value=runner), \
                    mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                exit_code = cri.main([
                    "--repo-root", str(root),
                    "--output", ".eliot/refused-inventory.json",
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                json.loads(stderr.getvalue()),
                {"status": "error", "code": "COMMAND_FAILED", "detail": detail},
            )
            self.assertFalse((root / ".eliot/refused-inventory.json").exists())
            self.assertEqual(runner.calls.count(_MEMBER_METADATA_COMMAND), 1)
            metadata_commands = [command for command in runner.calls if command[:2] == ("cargo", "metadata")]
            self.assertTrue(metadata_commands)
            for command in metadata_commands:
                self.assertIn("--locked", command)
                self.assertIn("--offline", command)


if __name__ == "__main__":
    unittest.main()
