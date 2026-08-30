#!/usr/bin/env python3
"""Deterministic fake Codex App Server used only by preflight tests."""
from __future__ import annotations

import json
import sys


def emit(value: object) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "success"
    for raw in sys.stdin:
        if mode == "malformed":
            sys.stdout.write("{not-json}\n")
            sys.stdout.flush()
            return 0
        if mode == "oversized":
            sys.stdout.write(json.dumps({"id": 1, "result": {"padding": "x" * 2_000_000}}) + "\n")
            sys.stdout.flush()
            return 0
        message = json.loads(raw)
        method = message.get("method")
        if method == "initialize":
            response = {"id": message.get("id"), "result": {"serverInfo": {"name": "fake-codex", "version": "test"}}}
            if mode == "jsonrpc":
                response["jsonrpc"] = "2.0"
            if mode == "mismatch-id":
                response["id"] = 999
            if mode == "server-error":
                response = {"id": message.get("id"), "error": {"code": "FAKE", "message": "synthetic"}}
            emit(response)
        elif method == "initialized":
            continue
        elif method == "model/list":
            cursor = message.get("params", {}).get("cursor")
            if cursor is None:
                models = [
                    {
                        "id": "fake-codex-a",
                        "displayName": "Fake Codex A",
                        "isDefault": True,
                        "hidden": False,
                        "supportedReasoningEfforts": ["medium", "high"],
                        "inputModalities": ["text"]
                    },
                    {
                        "id": "fake-codex-b",
                        "displayName": "Fake Codex B",
                        "isDefault": False,
                        "hidden": True,
                        "supportedReasoningEfforts": ["low"],
                        "inputModalities": ["text", "image"]
                    }
                ]
                if mode == "duplicate-model":
                    models.append(dict(models[0]))
                emit({"id": message.get("id"), "result": {"data": models, "nextCursor": "page-2"}})
            elif cursor == "page-2":
                emit({
                    "id": message.get("id"),
                    "result": {
                        "data": [
                            {
                                "id": "fake-codex-c",
                                "displayName": "Fake Codex C",
                                "isDefault": False,
                                "hidden": False,
                                "supportedReasoningEfforts": [],
                                "inputModalities": ["text"]
                            }
                        ],
                        "nextCursor": None
                    }
                })
            else:
                emit({"id": message.get("id"), "error": {"code": "BAD_CURSOR", "message": "synthetic"}})
        else:
            emit({"id": message.get("id"), "error": {"code": "FORBIDDEN_METHOD", "message": "synthetic"}})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
