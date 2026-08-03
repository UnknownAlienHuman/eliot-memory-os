# Development tool routing

## Source and diagnostics

Use Cargo and current files as the primary truth:

```powershell
cargo metadata --no-deps
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`just quick` is the bounded inner loop; `just verify` is the full Rust gate.
Rust Analyzer and code graphs may accelerate navigation, but compiler diagnostics
and exact source anchors decide current behavior.

## Runtime and integration tools

- Use the native SurrealDB CLI for server, import/export, readiness, and isolated
  operations tests. Configure its executable explicitly or make `surreal`
  discoverable through `PATH`.
- Use PowerShell for Windows packaging and operational scripts.
- Use provider CLIs only for concrete host integration validation. Provider auth
  remains provider-owned.
- For the C7-03C FTS admission repair, official SurrealDB documentation and the
  tagged v3.1.4 language test were consulted only to resolve the exact numbered
  OR-match/BM25 syntax; the result was then verified with the local native
  SurrealDB 3.1.4 CLI before changing the checked-in query.
- Node is a packaging-only dependency for the upstream MCPB validator; it is not
  part of the Governor runtime or agent hot path.

Local MCP registrations, code indexes, editor caches, and agent configuration are
developer-local and must not be committed.
