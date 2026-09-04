# Assignment reservation

Owning issue: #816
Implementation PR: #817
Branch: `work/816-curation-topology`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/smart/cognitive-wave-01.toml`, `crates/smart/cognitive-edge-map.toml`, `crates/smart/cognitive-crate-decisions.toml`, exact donor/legacy-owner clarifications in `crates/smart/cognitive-donor-map.toml`, and this temporary marker.

This single global metadata work unit reconciles both:

- Curation: 11 wire kinds, ten handler families, A-19c→A-20→mandatory A-31 screen gate, A-03 registry and contract-only handler/validation edges;
- Context: A-14a/A-06e projections→A-16a→A-17a→A-18→A-19r, with logical readiness separated from Rust linkage, A-17a as sole membership owner, A-15/F-STU measurement separation and A-19r planning without delivery ownership.

Preserve A-19r and A-19c as distinct stable order-19 tracks. Forbidden: any leaf `Cargo.toml`/`module.toml`/source/test, public schema, legacy consumer migration, runtime composition, root workspace/lockfile, workflow or normative-document edit.

Issue #816 plus its authoritative Context-topology extension comment are the complete execution contract. Rebase on actual current `main` before implementation and remove this marker before the pull request is marked ready.
