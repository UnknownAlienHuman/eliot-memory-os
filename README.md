# ELIOT Memory OS

> Pre-alpha — active development. Not ready for use.

ELIOT is a governed memory, understanding, and learning system for AI agents.

The repository contains the native Windows Rust Governor, canonical memory and
governance schemas, host integrations, deterministic tests, migrations, and the
operator application. [`docs/ARCHITECTURE_CONTRACT.md`](docs/ARCHITECTURE_CONTRACT.md)
separates current implementation truth from the canonical vision and future
design specifications.

## Development

MSVC Rust 1.96.1, pinned exactly by `rust-toolchain.toml`.

```powershell
cargo metadata --no-deps
cargo check --workspace --all-targets
cargo test --workspace
```

`just quick` provides the bounded metadata, formatting, and check loop. Cargo
output is redirected to `%LOCALAPPDATA%\Eliot\build\eliot-memory-os-target` by
the developer-local Cargo configuration. Runtime state belongs under the
configured per-user ELIOT data root and is never source-controlled.

The installed Windows credential boundary and its verification procedure are
documented in [`docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md`](docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md).

## License

ELIOT is licensed under the MIT License — see [`LICENSE`](LICENSE). That grant
is unconditional.

Third-party runtimes such as SurrealDB are **optional, separately licensed
components**, not parts of ELIOT. They are obtained and licensed by the operator
directly. ELIOT does not vendor, bundle, redistribute or link them; it reaches
them across a network protocol boundary over a transport implemented in this
repository rather than through a vendor SDK. That boundary is deliberate: it
keeps the dependency surface narrow and lets a capability — including the
canonical data store — be re-pointed at a different implementation without
redesign.

Where a capability can be satisfied by more than one component, ELIOT prefers
permissive open-source licenses, openly specified protocols with more than one
implementation, and independently addressable endpoints, and aims to document an
alternative or migration path for each dependency so that no operator is
compelled to accept terms they decline.

The full statement, including definitions and scope, is in
[`docs/DEPENDENCY_POLICY.md`](docs/DEPENDENCY_POLICY.md).
