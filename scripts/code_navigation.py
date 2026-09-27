#!/usr/bin/env python3
"""Navigate the current Cargo workspace, Rust files, logical blocks, and docs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from code_navigation_lib import (
    NavigationError,
    build_registry,
    check,
    render_blocks,
    render_crates,
    render_modules,
    render_route,
    route_payload,
    self_test,
)
from code_navigation_lib.capsules import (
    CAPSULE_ROOT,
    INDEX_PATH,
    build_capsules,
    check_capsules,
    emit_capsules,
)
from code_navigation_lib.package_docs import (
    check as check_package_docs,
    self_test as package_docs_self_test,
    write_index as write_package_docs_index,
)
from code_navigation_lib.prototype_docs import (
    check as check_prototype_docs,
    self_test as prototype_docs_self_test,
    write_index as write_prototype_docs_index,
)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    def add_root(command: argparse.ArgumentParser) -> None:
        command.add_argument("--root", type=Path, default=Path("."))

    check_parser = sub.add_parser("check")
    add_root(check_parser)
    self_test_parser = sub.add_parser("self-test")
    add_root(self_test_parser)
    pkg_self_test_parser = sub.add_parser("package-docs-self-test")
    add_root(pkg_self_test_parser)
    proto_self_test_parser = sub.add_parser("prototype-docs-self-test")
    add_root(proto_self_test_parser)
    sync_index_parser = sub.add_parser("sync-index")
    add_root(sync_index_parser)

    list_parser = sub.add_parser("list")
    add_root(list_parser)
    list_parser.add_argument("--view", choices=("crates", "modules", "blocks"), required=True)
    list_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

    route_parser = sub.add_parser("route")
    add_root(route_parser)
    route_parser.add_argument("--path", required=True)
    route_parser.add_argument("--topic")
    route_parser.add_argument("--format", choices=("text", "json"), default="text")

    capsules_parser = sub.add_parser(
        "capsules",
        help=(
            "Generate the mandatory I2.20 ModuleContractKit + CrateContextCapsule "
            "+ ModuleTestCapsule triad for every declared functional capability cell"
        ),
    )
    add_root(capsules_parser)
    capsules_parser.add_argument(
        "--emit",
        action="store_true",
        help=f"write every artifact and the index under {CAPSULE_ROOT}/",
    )
    capsules_parser.add_argument(
        "--check",
        action="store_true",
        help="fail closed when any artifact is absent or stale",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = args.root.resolve()
    try:
        if args.command == "self-test":
            self_test()
            package_docs_self_test()
            prototype_docs_self_test()
        elif args.command == "package-docs-self-test":
            package_docs_self_test()
        elif args.command == "prototype-docs-self-test":
            prototype_docs_self_test()
        elif args.command == "check":
            check(root)
            check_package_docs(root)
            check_prototype_docs(root)
        elif args.command == "sync-index":
            write_package_docs_index(root)
            write_prototype_docs_index(root)
            check_package_docs(root)
            check_prototype_docs(root)
        elif args.command == "list":
            registry = build_registry(root)
            if args.format == "json":
                print(json.dumps(registry, ensure_ascii=False, indent=2))
            elif args.view == "crates":
                print(render_crates(registry))
            elif args.view == "modules":
                print(render_modules(registry))
            else:
                print(render_blocks(registry))
        elif args.command == "route":
            payload = route_payload(root, args.path, args.topic)
            if args.format == "json":
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print(render_route(payload))
        elif args.command == "capsules":
            if args.check:
                failures = check_capsules(root)
                if failures:
                    print(f"CAPSULE_TRIAD_CHECK: FAIL issues={len(failures)}")
                    for failure in failures:
                        print(f"  - {failure}")
                    return 1
                print(f"CAPSULE_TRIAD_CHECK: PASS index={INDEX_PATH}")
                return 0
            summary = emit_capsules(root) if args.emit else None
            registry = build_capsules(root)["registry"]
            coverage = registry["capability_coverage"]
            header = [
                "CAPSULE_TRIAD: "
                f"cells={coverage['declared_capability_cells']} "
                f"artifacts={coverage['declared_capability_cells'] * 3} "
                f"reachable={coverage['reachable_packages']} "
                f"excluded={coverage['excluded_standalone_packages']} "
                f"ceiling={registry['support_ceiling_with_complete_triad']}"
            ]
            if summary is not None:
                header.append(f"written={summary['files_written']}")
            if registry["registry_defects"]:
                header.append(f"registry_defects={len(registry['registry_defects'])}")
            print(" ".join(header))
            for cell in registry["cells"]:
                support = cell["implementation_support"]
                defects = ",".join(support["blocking_codes"]) or "-"
                print(
                    f"  {support['implementation_support']} "
                    f"{cell['reachability']:<11} {cell['cell_id']} "
                    f"blocking={defects}"
                )
            if summary is not None:
                print(f"CAPSULE_TRIAD_WRITE: PASS index={INDEX_PATH} digest={summary['registry_digest'][:16]}")
        else:
            raise NavigationError(f"unsupported command: {args.command}")
    except NavigationError as exc:
        print(f"CODE_NAVIGATION_FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
