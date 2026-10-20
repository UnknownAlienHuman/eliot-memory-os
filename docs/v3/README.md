# Eliot Memory OS V3 — documentation

**Revision 0.9 · 2026-10-20.** Documentation before the greenfield rewrite; V1/V2 remain donors. This pass makes the useful learning path concrete rather than adding another qualification stage.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose, cognition, automatic learning and module boundaries; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Primary capture/read, background work, host/controller integration and practical recovery; remains 0.8 |
| [Cognition](COGNITION.md) | Current-state resolution, views, procedures and recursive improvement; 0.9 adds the connected episode-to-advice path |
| [Consolidated audit](AUDIT.md) | Sources and findings, 34 original requirements, 29 A15 cases and donors D01–D44 |
| [Audit map](AUDIT-MAP.md) | Actual coverage, missing producers/consumers and next reading |

## Current result

[Audit §24](AUDIT.md#24-from-an-episode-to-useful-learned-behavior--09) follows the retained V2 experience formation, abstraction, retrieval and applicability path, including its real SQL loader. It separates a supplied structured episode from actual semantic extraction; identifies word-overlap conditions, unreachable analogy branches, the oldest-512 window, filtering after the top-three cutoff and overbroad logical deduplication. D16 LangMem contributes a simpler trajectory-to-method proposal, with its no-change response handled explicitly.

[Cognition §6.8](COGNITION.md#68-one-episode-to-a-useful-next-attempt) connects a captured episode or explicit correction to a searchable provisional lesson and the next relevant context. One useful case need not pass a Case/Schema/Pattern/Transfer/Procedure ladder. Missing cause or verification stays unknown, not a reason to discard the example or invent missing fields. A no-change result retains the current method. Advice does not automatically execute a command.

[§5.2](COGNITION.md#52-select-useful-candidates-before-packing) separates candidate examination from final context size and keeps later corrections reachable. [§6.1](COGNITION.md#61-three-valued-matching) distinguishes observed conditions from mentions, negation and unknowns without a universal predicate prover. No new daemon, store, approval protocol or checklist family is added.

The 0.8 removal of global readiness dependencies remains: native primary reads work without a whole-project rebuild, graph threshold or diagnostic write; owner-selected recovery is not blocked by lost auxiliary history. Architecture, Implementation and their existing scenarios are unchanged. All previous audit sections and the thirty-six cognitive cases remain; the new worked learning example is a design illustration, not an executed V3 run.

## Continuing work

The next missing edge is the automatic episode producer from real host outcomes and the ordinary packet consumer of learned methods, beyond the manually supplied MCP form. The [map](AUDIT-MAP.md) also retains the remaining Harness2 executor/context and ORS/process reading; a search result does not mark those complete.

V2 source: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Earlier complete documentation remains in [Git history](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/feb5d814fcdfaeb5998b7b18da83d4995db1e433/docs/v3); archived research remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual publication and checks are reported there. Local ASCII/control-flow examples are not Rust, model or donor-runtime tests. No independent subagent review is claimed. Runtime, schemas, CI, the old ACTIVE registry and user data are unchanged; product implementation follows the documentation stage and the owner's code/minimum-Clippy/tests-later sequence.
