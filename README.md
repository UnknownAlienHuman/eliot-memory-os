# ELIOT Memory OS

> Pre-alpha — active development. Not ready for use.

ELIOT is a governed memory, understanding, and learning system for AI agents.

The repository contains the native Windows Rust Governor, canonical memory and
governance schemas, host integrations, deterministic tests, migrations, and the
operator application. [`docs/ARCHITECTURE_CONTRACT.md`](docs/ARCHITECTURE_CONTRACT.md)
defines the accepted Architecture 4.5 / Implementation 0.29 normative pair.
The canonical files are
[ELIOT Architecture](docs/architecture/ELIOT_ARCHITECTURE.md) and
[ELIOT Implementation](docs/architecture/ELIOT_IMPLEMENTATION.md); their exact
digests and adoption receipt are recorded in
[`docs/normative-pair.toml`](docs/normative-pair.toml). The dated 2026-08-28
English-final filenames are byte-identical publication aliases, not a second
pair. Use the [documentation index](docs/architecture/README.md) for bounded
routing.

Current project routing and the honest Runtime Live V3 boundary are summarized
in [`docs/PROJECT_MAP.md`](docs/PROJECT_MAP.md) and
[`reports/audit/RUNTIME_LIVE_V3_STATUS_2026-08-24.md`](reports/audit/RUNTIME_LIVE_V3_STATUS_2026-08-24.md);
these are routing/status documents, not acceptance evidence.

## Related repositories

ELIOT spans three repositories with one authority direction. This one is the core and the only
normative pair holder; the other two are separate products that attach as optional providers through
typed contracts.

| Repository | Owns |
|---|---|
| **eliot-memory-os** — this repository | Principal, WorkScope, task and authority; canonical records and history; Context Compiler; Governor, Dreamer, Watchdog and Doctor; verification and completion |
| [**eliot-search**](https://github.com/UnknownAlienHuman/eliot-search) | Local data preparation and retrieval: source identity and revisions, safe no-execute reads, materialization, exact/lexical/structural projections, publication and coherent readback |
| [**eliot-research**](https://github.com/UnknownAlienHuman/eliot-research) | External corpora at scale: acquisition, evidence library, corpus lens, research wiki and controlled investigations |

Neither provider is required for the first cognitive spine. A provider returns candidates, coverage,
freshness, provider assurance and reason codes; it never receives canonical credentials, task
authority, Context Compiler admission or finish authority. An absent or degraded provider narrows
declared coverage and is reported as a gap — it never transfers its responsibility to another owner
and never blocks unrelated local work.

## Development

MSVC Rust 1.97.1, pinned exactly by `rust-toolchain.toml`.

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
