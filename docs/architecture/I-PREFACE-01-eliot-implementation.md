# ELIOT Implementation
## Concrete implementation of a resilient Memory OS, Harness, Smart, and Meta in Rust

**Version:** 0.29-draft
**Date:** 2026-08-14
**Status:** target implementation contract; product `NOT_ACCEPTED / UNVERIFIED`; code, runtime, and data conformance unknown; repository cutover and removal of old books not accepted
**Normative pair:** `ELIOT_ARCHITECTURE.md` + `ELIOT_IMPLEMENTATION.md`
**English edition:** 2026-08-28; English revision with the final ownership, liveness, privacy, and residency closures incorporated
**Precedence:** On semantic conflict, this book is subordinate to Architecture 4.5-draft; local implementation cannot silently alter architectural intent
**Primary platform:** Windows 11 x64
**Control-plane language:** Rust 2024 edition
**Initial canonical substrate:** separate SurrealDB server through a replaceable storage bridge
**Primary operating mode:** local-first, demand-start, single-machine primary-user installation; multi-agent and multi-project within one local ELIOT
**Development constraint:** Normative detail and test count are not progress. Every agent change closes one causal property through an independently testable Module cell, real Instrument evidence, affected Edge Proof, and a bounded Product Pulse when the change can affect the overall result
**Crate strategy:** ELIOT is crate-rich and process-sparse: many independently selectable source/build units, fewer runtime bundles and processes, and exactly one lifecycle owner for each mutable state. Crate or source ownership grants no runtime authority. Each agent receives a route-qualified bounded causal workset; numeric context and size profiles remain measurable, replaceable Empirical Profiles—not Module or system limits

---

