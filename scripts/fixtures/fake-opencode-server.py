#!/usr/bin/env python3
"""Deterministic authenticated fake OpenCode HTTP server for preflight tests."""
from __future__ import annotations

import argparse
import base64
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def openapi_document(mode: str) -> dict[str, Any]:
    paths: dict[str, Any] = {
        "/global/health": {"get": {"operationId": "global.health"}},
        "/session": {"post": {"operationId": "session.create"}},
        "/session/{sessionID}/message": {"post": {"operationId": "session.message"}},
        "/session/{sessionID}/abort": {"post": {"operationId": "session.abort"}},
        "/event": {"get": {"operationId": "event.subscribe"}},
        "/provider": {"get": {"operationId": "provider.list"}},
        "/session/{sessionID}/fork": {"post": {"operationId": "session.fork"}},
        "/session/{sessionID}/children": {"get": {"operationId": "session.children"}},
    }
    if mode == "missing-abort":
        paths.pop("/session/{sessionID}/abort")
    if mode == "missing-event":
        paths.pop("/event")
    return {
        "openapi": "3.1.0",
        "info": {"title": "Fake OpenCode", "version": "test"},
        "paths": paths,
    }


def provider_catalogue(mode: str) -> dict[str, Any]:
    if mode == "empty-catalogue":
        return {"all": [{"id": "fake", "name": "Fake", "models": {}}], "default": {}, "connected": ["fake"]}
    models: Any = {
        "fake-model-a": {
            "id": "fake-model-a",
            "name": "Fake A",
            "limit": {"context": 128000, "output": 8192},
        },
        "fake-model-b": {
            "id": "fake-model-b",
            "name": "Fake B",
            "contextLimit": 64000,
            "outputLimit": 4096,
        },
    }
    if mode == "duplicate-model":
        models = [
            {"id": "duplicate", "name": "First"},
            {"id": "duplicate", "name": "Second"},
        ]
    return {
        "all": [{"id": "fake", "name": "Fake Provider", "models": models}],
        "default": {"fake": "fake-model-a"},
        "connected": ["fake"],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "FakeOpenCode/1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _authorized(self) -> bool:
        if self.server.mode == "unauthorized":  # type: ignore[attr-defined]
            return False
        expected = base64.b64encode(f"opencode:{self.server.password}".encode("utf-8")).decode("ascii")  # type: ignore[attr-defined]
        return self.headers.get("Authorization") == f"Basic {expected}"

    def _send_bytes(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, value: Any) -> None:
        self._send_bytes(status, json.dumps(value, separators=(",", ":")).encode("utf-8"))

    def do_GET(self) -> None:
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return
        mode = self.server.mode  # type: ignore[attr-defined]
        if self.path == "/global/health":
            self._send_json(200, {"healthy": mode != "unhealthy", "version": "fake-opencode-1.0"})
            return
        if self.path in {"/doc", "/openapi.json"}:
            if mode == "malformed-openapi":
                self._send_bytes(200, b"not-json")
            elif mode == "oversized-openapi":
                body = json.dumps({"openapi": "3.1.0", "paths": {}, "padding": "x" * (5 * 1024 * 1024)}).encode("utf-8")
                self._send_bytes(200, body)
            elif self.path == "/doc":
                self._send_json(200, openapi_document(mode))
            else:
                self._send_json(404, {"error": "not-found"})
            return
        if self.path in {"/config/providers", "/provider"}:
            if self.path == "/config/providers":
                self._send_json(404, {"error": "not-found"})
            elif mode == "malformed-provider":
                self._send_bytes(200, b"not-json")
            elif mode == "oversized-provider":
                body = json.dumps({"all": [], "padding": "x" * (3 * 1024 * 1024)}).encode("utf-8")
                self._send_bytes(200, body)
            else:
                self._send_json(200, provider_catalogue(mode))
            return
        self._send_json(404, {"error": "not-found"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--mode", default="success")
    arguments = parser.parse_args()
    if arguments.host != "127.0.0.1":
        raise SystemExit("fake server is loopback-only")
    password = os.environ.get("OPENCODE_SERVER_PASSWORD")
    if not password:
        raise SystemExit("OPENCODE_SERVER_PASSWORD is required")
    server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)
    server.password = password  # type: ignore[attr-defined]
    server.mode = arguments.mode  # type: ignore[attr-defined]
    try:
        server.serve_forever(poll_interval=0.05)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
