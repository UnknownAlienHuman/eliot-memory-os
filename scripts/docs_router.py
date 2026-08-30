#!/usr/bin/env python3
"""Route agents to exact normative sections and materialize lossless slices.

The accepted ELIOT Architecture/Implementation books remain immutable canonical
sources. This tool parses their stable section handles, selects the minimum
mandatory set for a task/path scope, and writes byte-exact section files plus a
content-addressed reading receipt.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

# Keep this executable directly runnable from the repository root and importable
# by unit tests without making scripts/ a Python package.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from docs_router_core import (  # noqa: E402
    DEFAULT_MAP,
    DEFAULT_RECEIPT,
    DOMAIN,
    RouterError,
    canonical_json,
    load_config,
    load_normative_pair,
    select_routes,
)
from docs_router_output import (  # noqa: E402
    check_all,
    emit_content,
    materialize_all,
    materialize_selected,
    print_catalog,
    render_route_markdown,
    write_json,
)
from docs_router_select import (  # noqa: E402
    build_receipt,
    resolve_selection,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--map", dest="map_path", type=Path, default=DEFAULT_MAP)
    parser.add_argument(
        "--receipt", dest="receipt_path", type=Path, default=DEFAULT_RECEIPT
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "check",
        help="validate pair identity, map selectors, and lossless reconstruction",
    )

    catalog = subparsers.add_parser(
        "catalog", help="print the discovered stable section catalog"
    )
    catalog.add_argument("--format", choices=("markdown", "json"), default="markdown")

    route = subparsers.add_parser("route", help="resolve a mandatory reading set")
    route.add_argument("--path", action="append", default=[])
    route.add_argument("--task", action="append", default=[])
    route.add_argument("--include-optional", action="store_true")
    route.add_argument("--allow-fallback", action="store_true")
    route.add_argument("--format", choices=("markdown", "json"), default="markdown")
    route.add_argument(
        "--content", action="store_true", help="emit selected source text after routing"
    )
    route.add_argument(
        "--exact-content",
        action="store_true",
        help="emit only exact bytes, without slice markers",
    )
    route.add_argument("--write-receipt", type=Path)

    materialize = subparsers.add_parser(
        "materialize", help="write physical byte-exact Markdown slices"
    )
    materialize.add_argument("--output", type=Path, required=True)
    materialize.add_argument(
        "--all", action="store_true", help="materialize the complete lossless root corpus"
    )
    materialize.add_argument("--path", action="append", default=[])
    materialize.add_argument("--task", action="append", default=[])
    materialize.add_argument("--include-optional", action="store_true")
    materialize.add_argument("--allow-fallback", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    try:
        pair, documents = load_normative_pair(repo_root, args.receipt_path)
        config = load_config(repo_root, args.map_path)

        if args.command == "check":
            result = check_all(repo_root, pair, config, documents)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.command == "catalog":
            print_catalog(documents, args.format)
            return 0

        if args.command == "route":
            if not args.path and not args.task:
                raise RouterError("route requires at least one --path or --task")
            selection = select_routes(config, args.path, args.task, args.allow_fallback)
            slices = resolve_selection(documents, selection, args.include_optional)
            receipt = build_receipt(
                repo_root,
                pair,
                config,
                documents,
                selection,
                slices,
                args.path,
                args.task,
                args.include_optional,
            )
            if args.write_receipt:
                write_json(args.write_receipt, receipt)
            if args.content or args.exact_content:
                emit_content(slices, documents, args.exact_content)
            elif args.format == "json":
                print(
                    json.dumps(
                        receipt, indent=2, ensure_ascii=False, sort_keys=True
                    )
                )
            else:
                print(render_route_markdown(receipt), end="")
            return 0

        if args.command == "materialize":
            output = (
                args.output if args.output.is_absolute() else repo_root / args.output
            )
            if args.all:
                if args.path or args.task:
                    raise RouterError("--all cannot be combined with --path or --task")
                manifest = materialize_all(output, pair, documents)
                print(
                    json.dumps(
                        manifest, indent=2, ensure_ascii=False, sort_keys=True
                    )
                )
                return 0
            if not args.path and not args.task:
                raise RouterError(
                    "materialize requires --all or at least one --path/--task"
                )
            selection = select_routes(config, args.path, args.task, args.allow_fallback)
            slices = resolve_selection(documents, selection, args.include_optional)
            receipt = materialize_selected(
                output,
                repo_root,
                pair,
                config,
                documents,
                selection,
                slices,
                args.path,
                args.task,
                args.include_optional,
            )
            print(
                json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True)
            )
            return 0

        raise AssertionError(f"unhandled command: {args.command}")
    except RouterError as exc:
        print(f"DOC_ROUTER_FAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
