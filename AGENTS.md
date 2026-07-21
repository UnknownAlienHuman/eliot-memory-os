# Repository agent instructions

## Source of truth

Current source files, `Cargo.toml`, `Cargo.lock`, Cargo diagnostics, tests, and
current documentation are authoritative. Generated indexes, agent memory, and
runtime database state are routing or evidence layers and may be stale.

## Working rules

- Prefer native Rust and PowerShell for the Windows development path.
- Do not add Python or Node services to the runtime path.
- Inspect exact source anchors and `cargo metadata --no-deps` before nontrivial
  Rust changes.
- Add dependencies only after reviewing features, license, MSRV, build cost, and
  existing workspace alternatives.
- Keep credentials, runtime state, reports, logs, build output, and local agent
  configuration outside Git.
- Use repository-relative paths, environment variables, or runtime discovery in
  source-controlled configuration.

## Verification

Run the smallest relevant checks while iterating. Before completion, use
`just quick` for bounded changes or `just verify` for real package changes, and
report every skipped or failing check honestly.
