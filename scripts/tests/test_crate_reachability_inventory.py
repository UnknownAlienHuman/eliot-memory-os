"""Unit tests for crate reachability and support-neutral inventory (issue #1133)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
