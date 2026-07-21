---
name: eliot-memory-discipline
description: Keep Eliot memory writes routed through SemanticCommand and WriterActor.
---

Write reports and observations through the existing SemanticCommand and WriterActor path when a durable memory write is required.

Use local hook spool only for F0 lifecycle capture and keep payloads bounded and redacted by the Rust hook processor.

Do not expose storage internals, database connection details, table names, or direct query surfaces through plugin files, hooks, skills, or MCP tools.
