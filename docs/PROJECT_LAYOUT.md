# Project layout

| Path | Purpose |
|---|---|
| `crates/` | Rust workspace source and Rust tests |
| `apps/` | Operator application source |
| `config/` | portable development configuration templates |
| `migrations/` | canonical top-level migration assets |
| `plugin/` | maintained host plugin source |
| `integrations/` | portable agent skills and host integration packages |
| `scripts/` | supported build, packaging, validation, and operations scripts |
| `tests/` | cross-language tests and deterministic fixtures |
| `docs/architecture/` | normative architecture and engineering contracts |
| `docs/operations/` | current operator runbooks |
| `docs/release/` | current packaging contract |

Build output belongs under `target/` or `dist/`. Per-user runtime data, reports,
logs, credentials, databases, and generated indexes are intentionally excluded
from Git.
