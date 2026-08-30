"""Deterministic synthetic regression fixtures for code navigation."""

from __future__ import annotations

import json
import tempfile
import textwrap
from pathlib import Path

from .common import NavigationError
from .registry import build_registry
from .routing import route_payload


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "crates/a/src").mkdir(parents=True)
        (root / "crates/b/src").mkdir(parents=True)
        (root / "docs/code-navigation").mkdir(parents=True)
        (root / "docs/architecture").mkdir(parents=True)
        (root / "scripts").mkdir(parents=True)
        (root / "AGENTS.md").write_text("# agents\n", encoding="utf-8")
        (root / "Cargo.toml").write_text(
            textwrap.dedent(
                """
                [workspace]
                members = ["crates/a", "crates/b"]
                default-members = ["crates/a"]

                [workspace.dependencies]
                b = { path = "crates/b" }
                """
            ).lstrip(),
            encoding="utf-8",
        )
        (root / "crates/a/Cargo.toml").write_text(
            textwrap.dedent(
                """
                [package]
                name = "a"
                version = "0.1.0"
                edition = "2024"

                [package.metadata.eliot]
                layer = "C1"
                purpose = "test package"
                source_maintenance_owner = "test"

                [dependencies]
                b.workspace = true
                """
            ).lstrip(),
            encoding="utf-8",
        )
        (root / "crates/b/Cargo.toml").write_text(
            textwrap.dedent(
                """
                [package]
                name = "b"
                version = "0.1.0"
                edition = "2024"
                """
            ).lstrip(),
            encoding="utf-8",
        )
        (root / "crates/a/src/lib.rs").write_text("pub mod work;\n", encoding="utf-8")
        (root / "crates/a/src/work.rs").write_text("pub fn run() {}\n", encoding="utf-8")
        (root / "crates/b/src/lib.rs").write_text("pub fn value() -> u8 { 1 }\n", encoding="utf-8")
        (root / "docs/code-navigation/logical-blocks.toml").write_text(
            textwrap.dedent(
                """
                schema_version = "eliot-code-navigation-v1"

                [[block]]
                id = "test"
                title = "Test"
                responsibility = "Synthetic test block."
                route_topic = "test source"
                path_globs = ["crates/**"]
                documentation_handles = ["A0.1"]
                """
            ).lstrip(),
            encoding="utf-8",
        )
        (root / "docs/architecture/handle-index.json").write_text(
            json.dumps(
                {
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {"A0.1": {"path": "x", "anchor": "a"}},
                }
            ),
            encoding="utf-8",
        )
        (root / "scripts/docs_router.py").write_text(
            textwrap.dedent(
                """
                from dataclasses import dataclass

                @dataclass
                class Route:
                    route_id: str

                def load_config(root):
                    return object()

                def matched_routes(config, paths, topic):
                    return [Route("test-route")]
                """
            ).lstrip(),
            encoding="utf-8",
        )

        registry = build_registry(root)
        if registry["counts"]["workspace_members"] != 2:
            raise NavigationError("self-test workspace member count mismatch")
        if registry["counts"]["rust_files"] != 3:
            raise NavigationError("self-test Rust file count mismatch")
        routed = route_payload(root, "crates/a/src/work.rs")
        if routed["package"]["name"] != "a":
            raise NavigationError("self-test package route mismatch")
        if routed["module"]["module_locator"] != "a::work":
            raise NavigationError("self-test module locator mismatch")
        local = routed["package"]["local_dependencies"]
        if not local or local[0]["root_path"] != "crates/b":
            raise NavigationError("self-test dependency edge mismatch")
        reverse = next(
            package for package in registry["packages"] if package["name"] == "b"
        )["reverse_dependencies"]
        if not reverse or reverse[0]["name"] != "a":
            raise NavigationError("self-test reverse dependency mismatch")
    print("CODE_NAVIGATION_SELF_TEST: PASS cases=6")
