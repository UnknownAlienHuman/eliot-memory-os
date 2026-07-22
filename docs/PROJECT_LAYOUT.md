# Project layout

| Path | Purpose |
|---|---|
| `crates/` | Rust workspace source and Rust tests |
| `apps/` | Operator application source |
| `config/` | portable development configuration templates |
| `migrations/` | canonical top-level migration assets |
| `integrations/` | portable agent skills and host integration packages |
| `scripts/` | supported build, packaging, validation, and operations scripts |
| `tests/` | cross-language tests and deterministic fixtures |
| `docs/architecture/` | canonical vision, current implementation architecture, and future design |
| `docs/operations/` | current operator runbooks |
| `docs/release/` | current packaging contract |

Rebuildable Cargo output belongs under
`%LOCALAPPDATA%\Eliot\build\eliot-memory-os-target`; generated host packages
belong under `%LOCALAPPDATA%\Eliot\packages`. A repository `dist/` is used only
by an explicit release-staging command. Per-user runtime data, reports, logs,
credentials, databases, and generated indexes are intentionally excluded from
Git.
