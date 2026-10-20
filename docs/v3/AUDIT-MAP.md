# V3 audit map

**Revision 0.8 · 2026-10-19.** Working coverage and next-reading map requested by the owner. [AUDIT.md](AUDIT.md) contains findings; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) contain the resulting design. This map does not control runtime access or implementation permissions.

Documentation base for this pass: `81a9848bccd95bc9778c4f9e92c210d6349eb298`, PR #5325. V2 source: `5aac094834fb5635921b550c821cb933a1196105`; V1 source: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The new source findings and removed V3 restrictions are in [audit §23](AUDIT.md#23-working-memory-without-global-gates-08). Earlier findings retain their stated scope; source reading is not a runtime test.

## Coverage

| Track | Covered | Still to read or establish | Decision carried into V3 |
|---|---|---|---|
| A01 Original requirements | Prior 34 requirements/29 A15 scenarios; V1 Production Architecture §0–1; V2 UserAutomation | Original autonomous learning and UL Part C beyond the retained excerpts; actual success-to-procedure consumers | Preserve understanding and self-learning, not the old proof/approval machinery |
| A02 Control and notifications | 0.7 broker dispatch, unavailable common approval gate, acknowledgement stitch, notification emitter/model and Store CAS/history | Alternative intake/delivery/recovery callers and actual toast feedback | Direct local control; current-state update plus needed history, not full-history replay |
| A03 Processes | Old I1.2 topology and selected broker lifetime checks | Daemon readiness, process-generation implementation and actual restart ownership | One real observer and normal process ownership; no duplicated supervisor/generation platform |
| A04 Storage and recovery | Previous backup/SDK/notification work; 0.8 Store projection claim wrapper 1860–2090 and full claim SQL; own restore contract revised | Full ORS responsibilities, primary capture/purge implementation and actual backup components | Primary records stay usable; independent jobs are not blocked by one old project row; owner can recover a selected backup without lost auxiliary history |
| A05 Cue and search | Old/new normalizers and retained consumer; 0.8 canonical_store.rs 2385–2500 now confirms all three 10,000 caps fail instead of paging | Source-producer path base; whether native primary search can replace remaining duplicated index families | Selected-ID hydration and native indexes first; page limit is not project capacity; no new cache framework to compensate for broad queries |
| A06 Context delivery | 0.7 MCP/InjectionPlanner chain; 0.8 activation.rs 1–300 and touched.rs 1–260; prior attach_boot path reconsidered | Actual transport handoff and session reset callers; useful context after newly ready orientation | Direct matches do not await optional graph or trace writes; presentation cache cannot permanently hide newly available material |
| A07 Development bureaucracy | Prior I2.20/AGENTS/workflow/approval findings | Actual latest CI failure and old receipt-gate scope, when integration is addressed | No fabricated reading certificates or new test platform; do not confuse a blocked check with working product behavior |
| A08 Own V3 overengineering | 0.8 removes blanket restore quarantine, synchronous re-proving of all sources, implicit mandatory tool gating and project-wide readiness dependencies | Cross-check concrete implementation once written, rather than inventing more generic contracts now | Serve known qualified memory, learn in background, keep optional extensions optional |
| A09 Hy coding memory | Previous writer/reconciliation/history/lexical findings and isolated probes | Only changed or uncovered paths relevant to a remaining feature | Preserve raw data, atomic revisions, distinct history and independent lexical candidates |
| A10 Hy transfer | Published 0.5/0.6 finite membership, conditions, no-change and feature-profile findings | Actual quality/runtime when a concrete transfer comparison needs it | Similarity proposes an analogy, not forced equivalence or new independent evidence |
| A11 Harness2 | Prior recursion, selection/reflection, library, ledger, schedule caller, guide and paper methods | Context/proposer/executor input and reset edges before taking code | Two improvement loops in existing jobs/controller; baseline/no-change stays eligible |
| A12 Other donors and archive | Original D01–D43 plus D44; 0.8 freshly reads D16 LangMem guides and reflection.py 1–560 at 48e3c11f | Full archived shortlist still not re-read; choose next donor by useful cognitive path, not inventory count | Separate reflection from reads; coalesce wakeups while preserving all unprocessed observations |
| A13 External interfaces | Prior Claude/SurrealDB/Windows source references; LangMem documentation and implementation compared in 0.8 | Actual installed host/controller methods, database schema/query and Windows behavior during implementation | A guide title or compatible field name does not prove the actual execution path |
| A14 Publication | 0.7 branch confirmed; 0.8 Implementation/Audit/Map/navigation prepared through GitHub API | Record actual new commit/ref and CI result in PR | Publish the changed documents, not another local-only handoff or inherited PASS claim |

## Next connected source passes

1. Follow an actual captured success/failure into a useful procedure and its later retrieval. Prioritize this cognitive consumer over another round of notification/control infrastructure. Revisit the original autonomous-learning requirements alongside that path.
2. Inspect source-producer path bases and transport/session reset edges only where they still affect the working context path. The loader truncation and activation dependencies above are now read; do not start over at their type declarations.
3. Separate ORS/process responsibilities into those the smaller V3 actually needs and those created by V2's removed topology. Inspect primary capture and practical backup/purge calls, not every historical receipt format.
4. Continue selected donor work: Harness2's actual proposal/execution context and a compact procedure-learning mechanism from the archive. D16's entire product and the whole donor archive are not marked audited by reading one executor.
5. Finish concrete host/controller/Store choices after the documentation decisions, then implement under the owner's product-code/minimum-Clippy/tests-later order.

## Boundaries of this pass

Fresh work is source analysis and documentation revision. No V2/V3 build, model call, LangMem execution, Windows/SurrealDB test, donor benchmark or independent subagent review was performed. Existing source findings are not re-labelled as newly reproduced failures. Runtime, schema, CI, validators, main, ACTIVE registry and user data are outside this change.

Keep this map small. Record source, useful finding and next action; do not create a file, signature, approval, percentage or mandatory checklist for each fact. A specific corrupt input can be rejected without disabling unrelated memory; a missing optional feature is a limitation, not a reason to stop the application.
