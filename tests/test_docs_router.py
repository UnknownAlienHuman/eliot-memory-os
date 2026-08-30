from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "docs_router.py"
SPEC = importlib.util.spec_from_file_location("docs_router", MODULE_PATH)
assert SPEC and SPEC.loader
router = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = router
SPEC.loader.exec_module(router)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


ARCHITECTURE = b"""# ELIOT Architecture\n\nPreamble.\n\n# A0. Constitution\n\n## A0.1. Purpose\nPurpose text.\n\n## A0.3. Hard Boundaries\nBoundary text.\n\n```text\n# A99. Not a heading\n```\n\n## A0.4. Conflict\nConflict text.\n\n# A1. Mission\nMission text.\n"""

IMPLEMENTATION = b"""# ELIOT Implementation\n\nPreamble.\n\n## **I0. Binding**\n\n### **I0.3. Target state**\nTarget.\n\n### **I0.4. Evidence**\nEvidence.\n\n### **I0.5. Support claims**\nClaims.\n\n### **I0.13. Profiles**\nProfiles.\n\n### **I0.14. Pair identity**\nIdentity.\n\n## **I1. Kernel**\n\n### **I1.1. Host**\nHost.\n\n## **I2. Modules**\nModules.\n\n## **I3. Agents**\nAgents.\n\n# Appendix A. Appendix\nAppendix.\n"""

MAP = """schema_version = "eliot-doc-router-v1"

[base]
required = ["A0.1", "A0.3", "I0.3..I0.5"]
optional = ["A0.4"]

[[route]]
id = "specific"
description = "specific route"
priority = 10
paths = ["crates/kernel/**"]
tasks = ["kernel"]
required = ["A1", "I1"]
optional = ["I-A"]

[[route]]
id = "generic"
description = "generic route"
priority = 1
paths = ["crates/**"]
tasks = ["module"]
required = ["I2"]
optional = []

[[route]]
id = "cross-cutting-fallback"
description = "fallback"
priority = 0
paths = []
tasks = ["cross-cutting-fallback"]
required = ["A0..A1", "I0..I3"]
optional = []
"""


class RepositoryFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        architecture_path = root / "docs/architecture/ELIOT_ARCHITECTURE.md"
        implementation_path = root / "docs/architecture/ELIOT_IMPLEMENTATION.md"
        architecture_path.parent.mkdir(parents=True)
        architecture_path.write_bytes(ARCHITECTURE)
        implementation_path.write_bytes(IMPLEMENTATION)
        (root / "docs/architecture/reading-map.toml").write_text(
            MAP, encoding="utf-8"
        )
        receipt = f'''schema_version = "eliot-normative-pair-v1"
status = "accepted"
pair_key = "sha256:{'a' * 64}"
architecture_path = "docs/architecture/ELIOT_ARCHITECTURE.md"
architecture_sha256 = "{digest(ARCHITECTURE)}"
implementation_path = "docs/architecture/ELIOT_IMPLEMENTATION.md"
implementation_sha256 = "{digest(IMPLEMENTATION)}"
'''
        (root / "docs/normative-pair.toml").write_text(receipt, encoding="utf-8")


class DocsRouterTests(unittest.TestCase):
    def load(self, root: Path):
        pair, documents = router.load_normative_pair(
            root, Path("docs/normative-pair.toml")
        )
        config = router.load_config(
            root, Path("docs/architecture/reading-map.toml")
        )
        return pair, documents, config

    def test_parser_ignores_fenced_heading_and_resolves_bold_handles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            RepositoryFixture(root)
            _, documents, _ = self.load(root)
            self.assertNotIn("A99", documents["architecture"].by_handle)
            self.assertIn("I0.14", documents["implementation"].by_handle)
            self.assertIn("I-A", documents["implementation"].by_handle)

    def test_complete_materialization_reconstructs_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            RepositoryFixture(root)
            pair, documents, _ = self.load(root)
            output = root / ".eliot-docs/all"
            manifest = router.materialize_all(output, pair, documents)
            for source_id, source in manifest["sources"].items():
                rebuilt = b"".join(
                    (output / block["file"]).read_bytes()
                    for block in source["blocks"]
                )
                self.assertEqual(rebuilt, documents[source_id].data)
                self.assertEqual(
                    source["canonical_sha256"], source["materialized_sha256"]
                )

    def test_selected_materialization_writes_exact_slices_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            RepositoryFixture(root)
            pair, documents, config = self.load(root)
            selection = router.select_routes(
                config, ["crates/kernel/control.rs"], [], False
            )
            slices = router.resolve_selection(
                documents, selection, include_optional=False
            )
            output = root / ".eliot-docs/task"
            receipt = router.materialize_selected(
                output,
                root,
                pair,
                config,
                documents,
                selection,
                slices,
                ["crates/kernel/control.rs"],
                [],
                False,
            )
            self.assertTrue((output / "reading-receipt.json").is_file())
            self.assertTrue((output / "README.md").is_file())
            self.assertEqual(len(receipt["materialized_files"]), len(slices))
            for record, item in zip(
                receipt["materialized_files"], slices, strict=True
            ):
                self.assertEqual(
                    (output / record["file"]).read_bytes(),
                    documents[item.source_id].data[item.start : item.end],
                )

    def test_specific_path_wins_over_generic_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            RepositoryFixture(root)
            _, documents, config = self.load(root)
            selection = router.select_routes(
                config,
                ["crates/kernel/control.rs"],
                [],
                allow_fallback=False,
            )
            self.assertEqual(
                [route.route_id for route in selection.routes], ["specific"]
            )
            self.assertIn("I1", selection.required_selectors)
            self.assertNotIn("I2", selection.required_selectors)
            slices = router.resolve_selection(
                documents, selection, include_optional=False
            )
            self.assertTrue(slices)

    def test_unknown_path_fails_closed_or_records_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            RepositoryFixture(root)
            _, _, config = self.load(root)
            with self.assertRaises(router.RouterError):
                router.select_routes(
                    config, ["unknown/file.rs"], [], allow_fallback=False
                )
            selection = router.select_routes(
                config, ["unknown/file.rs"], [], allow_fallback=True
            )
            self.assertEqual(selection.unknown_paths, ("unknown/file.rs",))
            self.assertIn(
                "cross-cutting-fallback",
                [route.route_id for route in selection.routes],
            )

    def test_receipt_is_content_addressed_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            RepositoryFixture(root)
            pair, documents, config = self.load(root)
            selection = router.select_routes(
                config, ["crates/kernel/control.rs"], ["kernel"], False
            )
            slices = router.resolve_selection(
                documents, selection, include_optional=True
            )
            first = router.build_receipt(
                root,
                pair,
                config,
                documents,
                selection,
                slices,
                ["crates/kernel/control.rs"],
                ["kernel"],
                True,
            )
            second = router.build_receipt(
                root,
                pair,
                config,
                documents,
                selection,
                slices,
                ["crates/kernel/control.rs"],
                ["kernel"],
                True,
            )
            self.assertEqual(first, second)
            payload = dict(first)
            recorded = payload.pop("receipt_sha256")
            self.assertEqual(
                recorded, digest(router.DOMAIN + router.canonical_json(payload))
            )

    def test_check_validates_all_selectors_and_partitions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            RepositoryFixture(root)
            pair, documents, config = self.load(root)
            result = router.check_all(root, pair, config, documents)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["sources"]["architecture"]["blocks"], 3)
            self.assertEqual(result["sources"]["implementation"]["blocks"], 6)


if __name__ == "__main__":
    unittest.main()
