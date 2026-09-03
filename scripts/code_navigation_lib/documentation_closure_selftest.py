"""End-to-end synthetic proof for package-to-documentation closure."""

from __future__ import annotations

import hashlib
import json
import tempfile
import textwrap
from pathlib import Path

from .common import NavigationError
from .documentation_closure import check


def _write_router(root: Path, digest: str) -> None:
    fragment = "docs/architecture/implementation/I02-08-test.md"
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "scripts/docs_router.py").write_text(
        textwrap.dedent(
            f"""
            from dataclasses import dataclass

            @dataclass(frozen=True)
            class Route:
                route_id: str

            @dataclass(frozen=True)
            class Config:
                routes: tuple[Route, ...]

            def load_config(root):
                return Config((Route("test-route"),))

            def matched_routes(config, paths, topic):
                if any(path == "crates" or path.startswith("crates/") for path in paths):
                    return [Route("test-route")]
                return []

            def route_payload(root, config, paths, topic):
                routes = matched_routes(config, paths, topic)
                if not routes:
                    raise RuntimeError("no route")
                return {{
                    "matched_routes": [route.route_id for route in routes],
                    "required": [{{
                        "kind": "fragment",
                        "path": "{fragment}",
                        "sha256": "{digest}",
                        "handles": ["I2.8"],
                        "anchors": ["i28-test"],
                    }}],
                    "optional": [],
                }}
            """
        ).lstrip(),
        encoding="utf-8",
    )


def _fixture(root: Path) -> str:
    (root / "crates/a/src").mkdir(parents=True)
    (root / "docs/code-navigation").mkdir(parents=True)
    fragment = root / "docs/architecture/implementation/I02-08-test.md"
    fragment.parent.mkdir(parents=True)
    fragment.write_text("# I2.8 Test\n", encoding="utf-8")
    digest = hashlib.sha256(fragment.read_bytes()).hexdigest()

    (root / "AGENTS.md").write_text("# Root agents\n", encoding="utf-8")
    (root / "crates/AGENTS.md").write_text("# Crate agents\n", encoding="utf-8")
    (root / "Cargo.toml").write_text(
        textwrap.dedent(
            """
            [workspace]
            members = ["crates/a"]
            default-members = ["crates/a"]
            resolver = "3"
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
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (root / "crates/a/src/lib.rs").write_text(
        "pub fn value() -> u8 { 1 }\n",
        encoding="utf-8",
    )
    (root / "docs/code-navigation/logical-blocks.toml").write_text(
        textwrap.dedent(
            """
            schema_version = "eliot-code-navigation-v1"

            [[block]]
            id = "test"
            title = "Test"
            responsibility = "Synthetic package documentation closure."
            route_topic = "test package"
            path_globs = ["crates/**"]
            documentation_handles = ["I2.8"]
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
                    "I2.8": {
                        "source": "implementation",
                        "title": "I2.8 Test",
                        "path": "docs/architecture/implementation/I02-08-test.md",
                        "anchor": "i28-test",
                        "source_anchor": "i28-test",
                        "fragment_sha256": digest,
                        "fragment_bytes": fragment.stat().st_size,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    block_table = (
        "| Block | Governing handles |\n"
        "|---|---|\n"
        "| `test` | [`I2.8`](../architecture/HANDLE_INDEX.md) |\n"
    )
    (root / "docs/code-navigation/PACKAGE_DOCS_INDEX.md").write_text(
        block_table
        + "\n| Package manifest | Admission | Logical blocks |\n"
        + "|---|---|---|\n"
        + "| [`crates/a`](../../crates/a/Cargo.toml) | `default` | `test` |\n",
        encoding="utf-8",
    )
    (root / "docs/code-navigation/PROTOTYPE_DOCS_INDEX.md").write_text(
        block_table,
        encoding="utf-8",
    )
    _write_router(root, digest)
    return digest


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _fixture(root)
        check(root)

        _write_router(root, "0" * 64)
        try:
            check(root)
        except NavigationError as exc:
            if "route binding differs from canonical handle index" not in str(exc):
                raise
        else:
            raise NavigationError("tampered route fragment digest was accepted")
    print("DOCUMENTATION_CLOSURE_E2E_SELF_TEST: PASS cases=2")
