# ADR 0006: Lossless OpenCode JSONC ownership

## Status

Accepted for Phase L7.

## Context

OpenCode officially accepts JSONC, including comments and trailing commas, in its user configuration. Eliot must add only `mcp.eliot`, preserve unrelated provider/auth/config state, and remove or restore only its owned entry during rollback. Parsing `opencode.jsonc` as strict JSON would reject valid user files; deserializing and pretty-printing the whole document would also discard comments.

## Decision

Use `jsonc-parser` 0.33.0 with only the `cst` and `serde_json` features in `eliot-app`.

- The concrete-syntax tree performs the smallest structural edit while retaining comments, trailing commas, and unrelated formatting.
- The semantic conversion is used only to compare the owned `mcp.eliot` value with the install manifest before update or rollback.
- The manifest records whether the `mcp` field existed before Eliot. Rollback removes an Eliot-created empty `mcp` container, restores a pre-existing `mcp.eliot`, or refuses when the owned value changed.
- Exact pre-install bytes remain backed up for unchanged-config rollback.

## Dependency review

- Source: crates.io / `https://github.com/dprint/jsonc-parser`
- Version: 0.33.0 (current at adoption on 2026-07-15)
- License: MIT
- Rust compatibility: edition 2024; compiled under the workspace Rust 1.89 MSRV gate
- Enabled optional dependencies: `serde_json` only; no Node/Python/service/runtime process is introduced
- Existing alternatives rejected: strict `serde_json` does not accept JSONC; a handwritten comment stripper or text scanner would be a second parser and would not provide lossless structural edits.

## Consequences

OpenCode global discovery now works for ordinary JSON and valid JSONC without erasing user comments. The app gains one small Rust parser dependency in the install/uninstall path; it does not enter the daemon, MCP, or provider hot path after installation.
