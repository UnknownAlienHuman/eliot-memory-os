# `eliot-context-candidates` implementation contract

Owning issue: [#604 — A-16a whole Context candidate construction](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/604).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is a target contract, not behavior.

## Mandatory documentation

Read through the repository router and then directly:

- [`I7.11 — Context payload profiles and Decision Safety Floor`](../../../docs/architecture/I07-11-context-payload-profiles-and-decision-safety-floor.md#i711-context-payload-profiles-and-decision-safety-floor)
- [`I12.13 — Context compiler`](../../../docs/architecture/I12-13-context-compiler.md#i1213-context-compiler)
- [`I12.26 — Memory admission and retrieval trace`](../../../docs/architecture/I12-26-memory-admission-and-retrieval-trace.md#i1226-memory-admission-and-retrieval-trace)
- [`I12.32 — Context economy ledger`](../../../docs/architecture/I12-32-context-economy-ledger.md#i1232-context-economy-ledger)
- [`I13.2 — Conflict Set`](../../../docs/architecture/I13-02-conflict-set.md#i132-conflict-set)
- [`I13.7 — Critical Attention`](../../../docs/architecture/I13-07-critical-attention.md#i137-critical-attention)
- [`I15.5 — Source assurance`](../../../docs/architecture/I15-05-source-assurance.md#i155-source-assurance)
- [`I15.6 — Instruction/data separation`](../../../docs/architecture/I15-06-instructiondata-separation.md#i156-instructiondata-separation)

## What to implement

Replace the placeholder with the deterministic pure A-16a mapper from exactly seven immutable provider roles to a bounded `ContextCandidateSet`: Task Frame; Attention/Conflict; Current Epistemic Position; supplied Cue Activation; negative memory; evidence/source assurance; affordances/capabilities.

## How

- Consume owner-neutral public contracts only; do not call provider, cue-activation, ranking, admission, assembly, Store or model implementations.
- Validate exact task/attempt/scope/fence, provider role denominator, schemas, revisions, digests, completeness states and independent bounds before mapping.
- Preserve each whole source member, provenance, semantic role, loss policy, measurement, conflicts, counterevidence, unknowns, privacy and proof ceilings.
- Give every provider/member/candidate one disposition. Missing, stale, partial, blocked and unknown cannot become complete or known-empty.
- Deduplicate only exact semantic identity while retaining all lineages. Equal-looking text with different identity remains distinct.
- Reserve representation for required/protected Safety-Floor roles before optional volume; this is not final Context admission.
- Keep instruction-like source content as data and emit explicit omissions/frontier on every bound.

## Acceptance

- The literal placeholder and `NOT_IMPLEMENTED` source status are removed only with cohesive implementation and package tests.
- Exactly seven roles are accepted; missing, duplicate or unexpected roles fail closed.
- All source members are mapped whole or receive an exact unsupported/omitted disposition.
- Required conflict, dissent, negative memory, unknowns and source gaps cannot be silently dropped.
- No provider query, ranking, final budget allocation, Context admission/assembly/delivery, authority, effect or Finish path exists.
- All 46 `WORK_UNIT_CASE: 604/1..46` tests from the issue execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains independently buildable and excluded from root workspace until #830 performs serialized admission.
