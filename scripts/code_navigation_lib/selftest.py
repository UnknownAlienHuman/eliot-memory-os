"""Deterministic synthetic regression fixtures for code navigation."""

from __future__ import annotations

import hashlib
import json
import tempfile
import textwrap
from pathlib import Path

from .common import NavigationError
from .cargo import inferred_targets, resolve_dependency_path
from .registry import build_registry
from .routing import route_payload
from .rust import module_locator


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "crates/a/src").mkdir(parents=True)
        (root / "crates/b/src").mkdir(parents=True)
        (root / "docs/code-navigation").mkdir(parents=True)
        (root / "docs/architecture").mkdir(parents=True)
        (root / "scripts").mkdir(parents=True)
        (root / "fragment.md").write_text("## A0.1. Test fragment\n", encoding="utf-8")
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
                documentation_route_ids = ["test-route"]
                """
            ).lstrip(),
            encoding="utf-8",
        )
        (root / "docs/architecture/handle-index.json").write_text(
            json.dumps(
                {
                    "schema_version": "eliot-handle-index-v1",
                    "handles": {
                        "A0.1": {
                            "source": "test",
                            "title": "A0.1. Test fragment",
                            "path": "fragment.md",
                            "anchor": "a01-test-fragment",
                            "source_anchor": "a01-test-fragment",
                            "fragment_sha256": "",
                            "fragment_bytes": 0,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        handle_index = json.loads(
            (root / "docs/architecture/handle-index.json").read_text(encoding="utf-8")
        )
        fragment = (root / "fragment.md").read_bytes()
        handle_index["handles"]["A0.1"]["fragment_sha256"] = hashlib.sha256(fragment).hexdigest()
        handle_index["handles"]["A0.1"]["fragment_bytes"] = len(fragment)
        (root / "docs/architecture/handle-index.json").write_text(
            json.dumps(handle_index), encoding="utf-8"
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
        target_root = root / "crates/targets"
        (target_root / "src/bin").mkdir(parents=True)
        (target_root / "examples").mkdir()
        (target_root / "tests").mkdir()
        (target_root / "benches").mkdir()
        (target_root / "build").mkdir()
        for relative in (
            "src/custom-lib.rs",
            "src/custom-bin.rs",
            "src/main.rs",
            "src/bin/auto-bin.rs",
            "examples/decl-example.rs",
            "examples/auto-example.rs",
            "tests/decl-test.rs",
            "tests/auto-test.rs",
            "benches/decl-bench.rs",
            "benches/auto-bench.rs",
            "build/custom.rs",
        ):
            (target_root / relative).write_text("fn main() {}\n", encoding="utf-8")
        target_manifest = {
            "package": {
                "name": "target-package",
                "autolib": False,
                "autobins": False,
                "autoexamples": False,
                "autotests": False,
                "autobenches": False,
                "build": "build\\custom.rs",
            },
            "lib": {"name": "renamed-lib", "path": "src/custom-lib.rs"},
            "bin": [{"name": "decl-bin", "path": "src\\custom-bin.rs"}],
            "example": [{"name": "decl-example", "path": "examples/decl-example.rs"}],
            "test": [{"name": "decl-test", "path": "tests/decl-test.rs"}],
            "bench": [{"name": "decl-bench", "path": "benches/decl-bench.rs"}],
        }
        targets = inferred_targets(target_root, target_manifest)
        if {(item["kind"], item["name"], item["path"]) for item in targets} != {
            ("lib", "renamed-lib", "src/custom-lib.rs"),
            ("bin", "decl-bin", "src/custom-bin.rs"),
            ("example", "decl-example", "examples/decl-example.rs"),
            ("test", "decl-test", "tests/decl-test.rs"),
            ("bench", "decl-bench", "benches/decl-bench.rs"),
            ("build", "build-script", "build/custom.rs"),
        }:
            raise NavigationError("explicit Cargo target matrix mismatch")
        custom_module = module_locator("target-package", "src/custom-bin.rs", targets)
        if custom_module["role"] != "binary" or custom_module["target_name"] != "decl-bin":
            raise NavigationError("custom Cargo target locator mismatch")
        custom_lib = module_locator("target-package", "src/custom-lib.rs", targets)
        if custom_lib["role"] != "crate-root" or custom_lib["module_locator"] != "target_package":
            raise NavigationError("custom library target locator mismatch")
        custom_build = module_locator("target-package", "build/custom.rs", targets)
        if custom_build["role"] != "build-script":
            raise NavigationError("custom build target locator mismatch")

        auto_root = root / "crates/auto"
        (auto_root / "src/bin").mkdir(parents=True)
        (auto_root / "src/bin/flat.rs").write_text("fn main() {}\n", encoding="utf-8")
        auto_targets = inferred_targets(auto_root, {"package": {"name": "auto"}})
        flat = module_locator("auto", "src/bin/flat.rs", auto_targets)
        if flat["role"] != "binary" or flat["module_locator"] != "auto::bin::flat":
            raise NavigationError("flat src/bin locator mismatch")
        if resolve_dependency_path(root, "crates/a", "../b", "package", "dependency") != "crates/b":
            raise NavigationError("dependency path normalization mismatch")
        for raw_path in ("../../../outside", "C:/outside"):
            try:
                resolve_dependency_path(root, "crates/a", raw_path, "package", "dependency")
            except NavigationError:
                pass
            else:
                raise NavigationError("dependency traversal was accepted")

        original_index = json.loads(
            (root / "docs/architecture/handle-index.json").read_text(encoding="utf-8")
        )
        for field, value in (
            ("path", "missing.md"),
            ("anchor", "tampered-anchor"),
            ("source_anchor", "tampered-source-anchor"),
            ("fragment_sha256", "0" * 64),
            ("fragment_bytes", 1),
        ):
            tampered = json.loads(json.dumps(original_index))
            tampered["handles"]["A0.1"][field] = value
            (root / "docs/architecture/handle-index.json").write_text(
                json.dumps(tampered), encoding="utf-8"
            )
            try:
                build_registry(root)
            except NavigationError:
                pass
            else:
                raise NavigationError(f"handle tamper was accepted: {field}")
        (root / "docs/architecture/handle-index.json").write_text(
            json.dumps(original_index), encoding="utf-8"
        )

        (root / "Cargo.toml").unlink()
        try:
            route_payload(root, "Cargo.toml")
        except NavigationError as exc:
            if "does not exist" not in str(exc):
                raise
        else:
            raise NavigationError("deleted Cargo.toml was accepted")

    print("CODE_NAVIGATION_SELF_TEST: PASS cases=14")
