# V3 audit map

**Revision 0.9 · 2026-10-20.** Working coverage and next-reading map, not a runtime gate. [Audit](AUDIT.md) holds findings; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) hold the design.

Base for this pass: `feb5d814fcdfaeb5998b7b18da83d4995db1e433`, PR #5325. V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. [Audit §24](AUDIT.md#24-from-an-episode-to-useful-learned-behavior--09) records the new learning-path findings. Earlier rows retain their previous source-level scope, not a fresh exhaustive audit.

| Track | Covered | Still to read or establish | Decision carried into V3 |
|---|---|---|---|
| A01 Original requirements and learning | Prior 34/29 maps and V1 excerpts; 0.9 V2 I12.21/I12.24; semantic_memory.rs 1–790 and 990–1240; skill.rs 1–255 | Automatic host-outcome→episode producer; downstream skill/packet consumers; original UL autonomy beyond retained excerpts | One episode may yield a useful provisional method; do not confuse a validated input form with semantic extraction or require a maturity ladder |
| A02 Control and notifications | Prior broker dispatch, unavailable common approval, acknowledgement stitch, notification state and CAS/history | Alternative intake/delivery/recovery callers and actual toast feedback | Direct local control and current-state update, not full-history replay |
| A03 Processes | Prior I1.2 topology and selected broker lifetime checks | Daemon readiness, process generations and actual restart ownership | One real observer; no duplicated supervisor/generation platform |
| A04 Storage and recovery | Prior SDK/backup/notification and projection-queue work; 0.9 semantic_records_by_kind.surql and actual MCP loader | ORS responsibilities, primary capture/purge/backup details; current indexed lesson query during implementation | A fixed oldest prefix is not a current semantic view; native lookup plus paged history |
| A05 Search and applicability | Prior cue paths; 0.9 need classifier, lexical applicability, recall ordering, projection keys and duplicate case references | Actual ordinary packet path beyond manual experience_recall; data structures' producer constraints as relevant | Search similarity is not satisfaction; examine candidates before the final output cutoff; retain distinct lessons/conditions |
| A06 Delivery | Prior MCP/InjectionPlanner/touched/activation findings | Actual transport/session reset and delivery of learned methods in the normal host path | Useful context does not wait for an observability receipt; manually callable tools alone do not complete automatic learning |
| A07 Development bureaucracy | Prior I2.20/AGENTS/workflow/approval findings; 0.9 relevant repository instructions | Actual CI failure and receipt-gate scope when integration is addressed | No fabricated reading certificates or new test bureaucracy |
| A08 Own V3 excess | Prior removal of global readiness/restore restrictions; 0.9 Cognition §§2,5.2,6.1,6.8 | Connect the described producer and consumer in later implementation; no new admission ladder | Direct correction or one useful interpreted episode is immediately eligible advice; keep means keep the existing method |
| A09 Hy coding memory | Previous writer/reconciliation/history/lexical findings and isolated probes | Changed or uncovered paths relevant to a remaining function | Preserve raw inputs, atomic revisions and independent lexical candidates |
| A10 Hy transfer | Published finite membership, conditions, no-change and feature-profile analysis | Actual quality/runtime only for a concrete later comparison | Similarity suggests analogy, not forced equivalence or independent support |
| A11 Harness2 | Prior recursion, selection/reflection, library, ledger, schedule caller, guide and paper methods | Context/proposer/executor input and reset edges before taking code | Two loops in existing jobs/controller; baseline/no-change remains eligible |
| A12 Other donors and archive | D01–D44; prior LangMem reflection executor; 0.9 D16 optimization.py 1–210, stateless.py through 290, prompt.py and official optimization docs | Whole archived shortlist still not re-read; further compact learning donors by actual need | Trajectory + optional feedback + current method gives a proposal; handle the no-change flag rather than returning an empty replacement |
| A13 External interfaces | Prior Claude/SurrealDB/Windows; LangMem code/doc comparison | Installed controller/host methods, Store plan and Windows behavior during implementation | A declared model result/field is not evidence of its downstream application |
| A14 Publication | Live 0.8 head/write permission read; 0.9 maintained documents prepared and isolated probes saved locally | Record actual final commit/ref and current CI in PR | Publish changes; never reuse an old PASS or independent-review claim for new bytes |

## Next connected reads

1. Trace automatic assembly of episode actions/outcomes from host events and the use of learned methods in an ordinary task packet. The manually supplied form→case→recall route is now examined; do not repeat its declarations or infer the missing producer from a tool name.
2. Follow downstream skill selection/execution only where it differs from this retained experience route. Distinguish a useful counterexample from a claim that every alternative V2 path is broken.
3. Finish Harness2 context/proposer/executor inputs and reset behavior, then select another donor mechanism only for a remaining cognitive need. D16's no-change mismatch is not a fresh audit of all LangMem.
4. Continue remaining ORS/process ownership and source/transport edges. Keep necessary recovery behavior while removing responsibilities created by the discarded topology.
5. Resolve actual host/controller/Store choices, then implement connected product paths under the owner's code/minimum-Clippy/tests-later order.

## Check boundary

This pass uses source reading and isolated Python ports/logical examples: three ASCII token matches, applicability branch reachability up to five conditions, candidate cutoff order, projection grouping, oldest-prefix visibility and a no-change response. They are not a Rust build, live DB/model call or donor benchmark. Supporting scripts stay outside the product tree. No independent subagent review, whole archive re-read or whole-repository coverage percentage is claimed.

Preserve counterchecks: reconstructed cases can be exposed in V2 under IncludeCaseCandidates; explicit requested_need can override the default; material_unknowns can cause RequireProbe even after a word match. These exceptions limit the findings. Product code, schema, CI, validators, main, ACTIVE registry and user data are unchanged by this documentation pass.
