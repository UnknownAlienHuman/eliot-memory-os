# ELIOT Memory OS

> Pre-alpha — active development. Not ready for use.

ELIOT is a governed memory, understanding, and learning system for AI agents.

The repository contains the native Windows Rust Governor, canonical memory and
governance schemas, host integrations, deterministic tests, migrations, and the
operator application. Current architecture and engineering contracts live under
`docs/architecture`.

## Development

Use stable MSVC Rust as pinned by `rust-toolchain.toml`.

```powershell
cargo metadata --no-deps
cargo check --workspace --all-targets
cargo test --workspace
```

`just quick` provides the bounded metadata, formatting, and check loop. Runtime
state belongs under `.eliot-governor` or the configured per-user data root and is
never source-controlled.
