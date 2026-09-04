# Assignment reservation

Owning issue: #783
Implementation PR: #784
Branch: `fix/783-app-context-measurement`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/eliot-app/Cargo.toml`, exact package-local semantic Context/MCP/token estimate call sites frozen by the #783 inventory, package-local tests/fixtures, and this temporary marker. Migrate only `eliot-app` consumers to integrated F-STU-0 #704 over exact serialized bytes while preserving actual-versus-estimated state, serializer/route/tokenizer identity and memory/MCP semantics.

Forbidden: F-STU-0/A-15 owners, `eliot-engine`, `eliot-types`, root workspace/lockfile, scripts/oracles/workflows/docs, or measurement-driven ranking/lifecycle/support/admission changes. Measurement failure never restores a local ratio. Remove this marker before ready.
