# ELIOT Memory OS

> Pre-alpha — active development. Not ready for use.

ELIOT is a governed memory, understanding, and learning system for AI agents.
This repository owns the Rust control plane, canonical contracts, runtime
processes, integrations, tests, and the only normative Architecture/
Implementation pair for ELIOT core.

## Work starts here

- **Current source and documentation:** `main` only.
- **Agent rules:** [`AGENTS.md`](AGENTS.md).
- **Branch/worktree workflow:** [`WORKFLOW.md`](WORKFLOW.md).
- **Active programmes:** [`workstreams/ACTIVE.toml`](workstreams/ACTIVE.toml).
- **Current product/source map:** [`docs/PROJECT_MAP.md`](docs/PROJECT_MAP.md).
- **Supported repository scripts:** [`scripts/README.md`](scripts/README.md).
- **GitHub workflows/templates:** [`.github/README.md`](.github/README.md).

Do not continue work from a branch found in local history, agent memory, or an
old conversation. Fetch/prune, fast-forward `main`, and create a fresh
issue-numbered branch. A nonstandard branch is mutable only when
`workstreams/ACTIVE.toml` contains an explicit temporary exception; there are no
active exceptions currently.

## Canonical documentation

[`docs/ARCHITECTURE_CONTRACT.md`](docs/ARCHITECTURE_CONTRACT.md) establishes the
accepted normative pair:

- [ELIOT Architecture](docs/architecture/ELIOT_ARCHITECTURE.md), revision
  `4.5-draft`;
- [ELIOT Implementation](docs/architecture/ELIOT_IMPLEMENTATION.md), revision
  `0.29-draft`.

Exact digests and adoption identity are in
[`docs/normative-pair.toml`](docs/normative-pair.toml). Use the
[documentation index](docs/README.md) to load only the relevant sections.
Documentation describes intent and target contracts; it does not prove that a
capability is built, installed, running, or accepted.

Historical audits, recovery programmes, donor research, progress diaries, and
generated/local agent state are intentionally absent from the active checkout.
Git history and issue/PR records preserve archaeology without presenting it to
agents as current authority.

## Related repositories

| Repository | Owns |
|---|---|
| **eliot-memory-os** | Principal, WorkScope, tasks, authority, canonical records/history, Context Compiler, Governor, Dreamer, Watchdog, Doctor, verification and finish |
| [**eliot-search**](https://github.com/UnknownAlienHuman/eliot-search) | Local source preparation and retrieval projections behind typed provider contracts |
| [**eliot-research**](https://github.com/UnknownAlienHuman/eliot-research) | External-corpus acquisition and evidence-library services behind typed provider contracts |

External-project design documents remain in their own repositories. Providers
return candidates, coverage, freshness, assurance, and reason codes; they never
receive canonical credentials, task authority, Context Compiler admission, or
finish authority.

## Development

MSVC Rust 1.97.1 is pinned by `rust-toolchain.toml`.

```powershell
cargo metadata --no-deps
just quick
```

Use focused package/edge proofs while iterating. Run wider checks only for a
matching blast radius and report every skipped or unavailable check honestly.
Cargo output, runtime state, reports, logs, generated code-graph databases, and
machine-local agent state stay outside Git.

Windows credential operations are documented in
[`docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md`](docs/operations/SURREALDB_CREDENTIAL_AUTHORITY.md).

## License

ELIOT is licensed under the MIT License — see [`LICENSE`](LICENSE). Optional
third-party runtimes remain separately obtained and licensed components behind
replaceable ELIOT-owned protocol boundaries. See
[`docs/DEPENDENCY_POLICY.md`](docs/DEPENDENCY_POLICY.md).
