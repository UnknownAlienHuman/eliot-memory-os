from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_docs_links.py"
SPEC = importlib.util.spec_from_file_location("check_docs_links", MODULE_PATH)
assert SPEC and SPEC.loader
links = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = links
SPEC.loader.exec_module(links)


class DocsLinkTests(unittest.TestCase):
    def test_valid_relative_links_and_duplicate_github_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs/guide.md").write_text(
                "# Same heading\n\n# Same heading\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "# Home\n\n[Guide](docs/guide.md#same-heading-1)\n"
                "[Local](#home)\n",
                encoding="utf-8",
            )
            files = links.markdown_files(root, [Path(".")])
            self.assertEqual(links.check_links(root, files), [])

    def test_missing_target_and_anchor_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text(
                "# Home\n\n[Missing](missing.md)\n[Bad anchor](#absent)\n",
                encoding="utf-8",
            )
            files = links.markdown_files(root, [Path(".")])
            failures = links.check_links(root, files)
            self.assertEqual(len(failures), 2)
            self.assertIn(
                "target does not exist", {failure.reason for failure in failures}
            )
            self.assertTrue(
                any("anchor #absent" in failure.reason for failure in failures)
            )

    def test_links_inside_code_fences_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text(
                "# Home\n\n```markdown\n[Not real](missing.md)\n```\n",
                encoding="utf-8",
            )
            files = links.markdown_files(root, [Path(".")])
            self.assertEqual(links.check_links(root, files), [])


if __name__ == "__main__":
    unittest.main()
