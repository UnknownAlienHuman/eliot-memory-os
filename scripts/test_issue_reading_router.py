"""Behavioral regressions for the Issue-declared documentation reader (#5320)."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import docs_router as router
import docs_read as reader
import docs_shards as shards


class IssueReadingTests(unittest.TestCase):
    def test_01_fenced_list_is_example_not_reading(self):
        # WORK_UNIT_CASE: 5320/1
        body = "## Read\n- I0.14\n```text\n- I9.9\n- unrelated.md\n```\n"
        self.assertEqual(router.parse_issue_reading(body), (("I0.14",), ()))

    def test_02_short_or_named_fence_does_not_close(self):
        # WORK_UNIT_CASE: 5320/2
        body = "## Read\n- I0.14\n````text\n```\n- I9.9\n````info\n- wrong.md\n````\n"
        self.assertEqual(router.parse_issue_reading(body), (("I0.14",), ()))

    def test_03_indented_fence_is_not_a_closer(self):
        # WORK_UNIT_CASE: 5320/3
        body = "## Read\n- I0.14\n~~~\n    ~~~\n- wrong.md\n~~~\n"
        self.assertEqual(router.parse_issue_reading(body), (("I0.14",), ()))

    def test_04_duplicate_section_after_other_heading_refuses(self):
        # WORK_UNIT_CASE: 5320/4
        with self.assertRaisesRegex(router.RouteError, "duplicate"):
            router.parse_issue_reading("## Read\n- I0.14\n## Work\ntext\n## Читать\n- I5.26\n")

    def test_05_hidden_or_hash_suffixed_heading_is_not_declaration(self):
        # WORK_UNIT_CASE: 5320/5
        self.assertIsNone(router.parse_issue_reading("<!--\n## Read\n- I9.9\n-->\n## Read#\n- I0.14\n"))

    def test_06_exact_live_body_bytes_not_stdout_framing(self):
        # WORK_UNIT_CASE: 5320/6
        body = "## Read\r\n- I0.14\r\n"
        result = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"body": body, "number": 5320}) + "\n")
        with patch.object(router.subprocess, "run", return_value=result):
            self.assertEqual(router.fetch_issue_body(ROOT, "5320"), body)

    def test_07_wrong_or_malformed_live_identity_refuses(self):
        # WORK_UNIT_CASE: 5320/7
        for payload in (["wrong"], {"number": 5321, "body": "## Read\n- I0.14"}):
            with self.subTest(payload=payload):
                result = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(payload))
                with patch.object(router.subprocess, "run", return_value=result), self.assertRaises(router.RouteError):
                    router.fetch_issue_body(ROOT, "5320")

    def test_08_offline_bytes_preserve_crlf_and_final_newline(self):
        # WORK_UNIT_CASE: 5320/8
        raw = b"## Read\r\n- I0.14\r\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "issue.md"
            path.write_bytes(raw)
            declared = router.load_declared_reading(ROOT, None, path)
        self.assertEqual(declared.body_sha256, hashlib.sha256(raw).hexdigest())
        self.assertIn("Issue body file", declared.source)

    def test_09_handle_and_same_file_have_one_payload(self):
        # WORK_UNIT_CASE: 5320/9
        declared = router.declared_reading_from_body("## Read\n- I0.14\n- docs/architecture/I00-14-documentation-and-evidence-build-integrity.md\n", "fixture")
        route = router.route_payload(ROOT, router.load_config(ROOT), [], "", declared)
        paths = [item["path"] for item in route["required"]]
        self.assertEqual(len(paths), len(set(paths)))
        item = next(item for item in route["required"] if item["path"].endswith("I00-14-documentation-and-evidence-build-integrity.md"))
        self.assertIn("I0.14", item["handles"])
        self.assertEqual(route["required_bytes"], sum(item["bytes"] for item in route["required"]))

    def test_10_topic_cannot_silently_expand_issue_read(self):
        # WORK_UNIT_CASE: 5320/10
        declared = router.declared_reading_from_body("## Read\n- I0.14\n", "fixture")
        with self.assertRaisesRegex(router.RouteError, "declare them explicitly"):
            router.route_payload(ROOT, router.load_config(ROOT), [], "parallel agent development contract", declared)

    def test_11_declared_file_keeps_owner_instructions(self):
        # WORK_UNIT_CASE: 5320/11
        declared = router.declared_reading_from_body("## Read\n- crates/governor/eliot-config/Cargo.toml\n", "fixture")
        route = router.route_payload(ROOT, router.load_config(ROOT), [], "", declared)
        self.assertTrue({"AGENTS.md", "crates/AGENTS.md", "crates/governor/AGENTS.md"}.issubset({item["path"] for item in route["required"]}))
        self.assertEqual(route["paths"], [])

    def test_12_optional_inventory_is_explicit_opt_in(self):
        # WORK_UNIT_CASE: 5320/12
        route = router.route_payload(ROOT, router.load_config(ROOT), ["scripts/docs_router_core.py"], "")
        compact = router.render_route(route)
        full = router.render_route(route, full_pointers=True)
        self.assertLess(len(compact), len(full))
        optional_path = route["optional"][0]["path"]
        self.assertNotIn(optional_path, compact)
        self.assertIn(optional_path, full)
        self.assertIn("--full-pointers", compact)

    def test_13_rendered_source_cannot_close_outer_fence(self):
        # WORK_UNIT_CASE: 5320/13
        source = "````\n## Read\n- fake.md\n````\n"
        rendered = reader.render_item({"path": "sample.py", "sha256": "a" * 64, "bytes": len(source)}, source)
        self.assertIn("`````python\n", rendered)
        self.assertTrue(rendered.endswith("`````\n"))

    def test_14_protocol_sync_preserves_rules_and_machine_template(self):
        # WORK_UNIT_CASE: 5320/14
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs/architecture").mkdir(parents=True)
            (root / "crates/example").mkdir(parents=True)
            (root / ".github").mkdir()
            pair_id = shards._core.pair_key("a" * 64, "b" * 64)
            (root / "docs/normative-pair.toml").write_text(f'architecture_sha256="{"a" * 64}"\nimplementation_sha256="{"b" * 64}"\npair_key="{pair_id}"\n', encoding="utf-8")
            block = "<!-- eliot-doc-routing:start -->\nold\n<!-- eliot-doc-routing:end -->"
            owner = root / "crates/example/AGENTS.md"
            owner.write_bytes(("# Owner\r\nrule before\r\n" + block + "\r\nrule after\r\n").encode("utf-8"))
            (root / "AGENTS.md").write_text("# Root\n" + block + "\n", encoding="utf-8")
            (root / "docs/architecture/READING_PROTOCOL.md").write_text("old", encoding="utf-8")
            entry = root / "docs/architecture/README.md"
            entry.write_text("old entry", encoding="utf-8")
            template = root / ".github/pull_request_template.md"
            template.write_text("MACHINE EVIDENCE MUST SURVIVE", encoding="utf-8")
            shards.sync_reading_protocol(root)
            text = owner.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("# Owner\nrule before\n"))
            self.assertTrue(text.endswith("\nrule after\n"))
            self.assertTrue(owner.read_bytes().startswith(b"# Owner\r\nrule before\r\n"))
            self.assertTrue(owner.read_bytes().endswith(b"\r\nrule after\r\n"))
            self.assertIn("../../docs/architecture/READING_PROTOCOL.md", text)
            self.assertIn("read --issue <number> --path", entry.read_text(encoding="utf-8"))
            self.assertIn("optional pointers", entry.read_text(encoding="utf-8"))
            self.assertEqual(template.read_text(encoding="utf-8"), "MACHINE EVIDENCE MUST SURVIVE")
            self.assertEqual(shards.sync_reading_protocol(root, check=True), [])

    def test_15_external_or_invalid_declared_paths_refuse(self):
        # WORK_UNIT_CASE: 5320/15
        for value in ("C:/Windows/win.ini", "D:relative.md", "//server/share/file.md", "../outside.md", "bad\x00.md"):
            with self.subTest(value=value), self.assertRaises(router.RouteError):
                router.declared_reading_from_body(f"## Read\n- `{value}`\n", "fixture")

    def test_16_resolved_external_file_cannot_enter_route_or_bundle(self):
        # WORK_UNIT_CASE: 5320/16
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repo"
            root.mkdir()
            outside = base / "outside.md"
            outside.write_text("external sentinel", encoding="utf-8")
            candidate = root / "alias.md"
            resolve = Path.resolve

            # Model the filesystem resolution of a junction/symlink without
            # requiring Windows symbolic-link privileges on the test host.
            def redirected(path, *args, **kwargs):
                return outside if path == candidate else resolve(path, *args, **kwargs)

            with patch.object(Path, "resolve", redirected):
                with self.assertRaisesRegex(router.RouteError, "escapes repository"):
                    router.file_record(root, "alias.md", "required")
                with self.assertRaisesRegex(router.RouteError, "escapes repository"):
                    reader.verified_item(root, {"path": "alias.md", "bytes": 17, "sha256": "a" * 64})

    def test_17_indexed_fragment_paths_obey_repository_boundary(self):
        # WORK_UNIT_CASE: 5320/17
        for value in ("C:/Windows/win.ini", "D:relative.md", "../outside.md"):
            handles = {"A1": {"path": value, "fragment_sha256": "a" * 64, "fragment_bytes": 1, "anchor": "example"}}
            with self.subTest(value=value):
                with self.assertRaises(router.RouteError):
                    router.fragment_records(["A1"], handles, "required", root=ROOT)
                payload = {"required": [{"kind": "fragment", "path": value, "sha256": "a" * 64, "handles": ["A1"]}], "optional": []}
                with self.assertRaises(router.RouteError):
                    router.assert_required_handles(ROOT, handles, payload, ["A1"], "fixture")


if __name__ == "__main__":
    unittest.main()
