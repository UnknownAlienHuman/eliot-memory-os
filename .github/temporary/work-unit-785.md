# Assignment reservation

Owning issue: #785
Implementation PR: #786
Branch: `fix/785-engine-context-measurement`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/eliot-engine/Cargo.toml`, exact package-local semantic Context/packet-quality/Skill/host estimate call sites frozen by the #785 inventory, package-local tests/fixtures, and this temporary marker. Migrate only `eliot-engine` consumers to integrated F-STU-0 #704, remove local semantic ratios and duplicate Skill estimators, preserve actual/estimated/unknown units and leave admission, packet semantics, Skill lifecycle and genuine byte/line limits unchanged.

Forbidden: F-STU-0/A-15 owners, `eliot-app`, `eliot-types`, root workspace/lockfile, scripts/oracles/workflows/docs, or measurement-driven semantic/lifecycle changes. Remove this marker before ready.
