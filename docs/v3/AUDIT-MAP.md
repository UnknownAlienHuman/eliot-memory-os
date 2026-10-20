# V3 audit map — coverage and remaining design work

**Revision 0.18 · 2026-10-20.** This answers the owner's coverage question. It does not declare the design complete, add a runtime registry or require a new approval process. [AUDIT.md](AUDIT.md) holds source findings; [Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) hold the product design.

Base: `4a0616ccb087a4edb8018f1ae07c348d4b1e2dc6`, PR #5325. V2 donor: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Detailed earlier reading ranges remain in the immutable [0.17 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/4a0616ccb087a4edb8018f1ae07c348d4b1e2dc6/docs/v3/AUDIT-MAP.md), [0.16 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/966650aa71d24cd75a6d214a4f46ab2d832af36a/docs/v3/AUDIT-MAP.md) and their linked predecessors. This reconciliation does not turn that partial reading into whole-repository review.

## 1. What can honestly be claimed

- **All donors studied: no.** D01–D44 is an inventory of surfaces, not 44 completed source audits. Thirteen entries have identifiable function-level source findings in the maintained V3 audit; three have documentation/paper-level treatment in this accounting; the other twenty-eight remain inherited or insufficiently reconciled for a current source-review claim. These categories describe recorded coverage, not a percentage of total understanding or a claim that the thirteen products were read in full.
- **All audits checked: no.** The supplied Claude revision 4, earlier owner reports and selected archive findings have informed the design. There is no complete audit-by-audit, finding-by-finding reconciliation against the chosen V3 boundary. Historical fixes and recommendations are not automatically current requirements.
- **V3 concept understood: the central design is explicit.** Preserve actual observations; interpret useful episode material through a real model; retain revisable knowledge; deliver applicable content; observe subsequent outcomes. Owners and rejected V2 machinery are stated.
- **Complete implementation model: not yet.** Specific external request/result routes, concrete storage operations, host event mapping, the practical learning/refresh policy and the remaining original-purpose reconciliation still need a connected treatment. Those are design tasks, not reasons to create another qualification framework.

The retained 34 requirement groups and 29 A15 scenarios are navigation and preservation aids. Their presence does not prove that every original requirement has been independently reconciled or implemented. The supplied Claude audit uses 63 Architecture anchors and eight hard boundaries; those are different denominators and cannot be silently equated with the 34 grouped rows.

## 2. D01–D44: conservative coverage census

**Source excerpts** means named functions/callers were inspected and findings recorded; surrounding paths may remain unread. **Docs/paper** does not qualify the implementation. **Unreconciled** means the current V3 record does not establish a comparable function-level review; it does not assert that nobody ever read anything about this donor in an earlier audit. Selecting a mature tool need not entail auditing its entire implementation.

| D | Donor surface | Recorded level | Useful next question / retained limit |
|---|---|---|---|
| 01 | MemMachine | Source excerpts, §§26–27 | Actual configured backend and remaining segmenter/ingestion details; do not generalize one backend |
| 02 | MemPalace | Unreconciled | Source identities and repeated export handling |
| 03 | Subcog | Source excerpts, §28 | Selected fusion/lifecycle functions, not complete runtime quality |
| 04 | MemOS local plugin | Source excerpts, §9 | L2/gain attribution only; not the complete learning pipeline |
| 05 | Claude Code memory/tool search | Docs/paper | Installed event/decision timing and actual integration, not source audit of the host |
| 06 | ClawVM | Unreconciled | What compression actually preserves and what the next reader sees |
| 07 | Pichay / demand paging | Unreconciled | Repeated expansion cost and reconstruction behavior |
| 08 | Graphiti | Source excerpts, §26 | Temporal filters and actual add_episode caller before broadening helper findings |
| 09 | Hindsight | Source excerpts, §§26–27 | Remaining retain-to-consolidation/storage paths and broader retrieval |
| 10 | Current EverOS | Source excerpts, §30 | Imported everalgo internals and unreviewed intake/recovery paths |
| 11 | Historical EverMemOS | Docs/paper, §30 | Historical implementation matching the paper is not established |
| 12 | Cloudflare managed Agent Memory | Unreconciled | Actual service boundary and useful capture/update mechanism |
| 13 | Cloudflare Agents SDK Sessions | Unreconciled | Session/branch/compaction semantics relevant to source intake |
| 14 | SurrealFS | Unreconciled | Source/indexer identity and incremental indexing, not another Store |
| 15 | MentisDB | Unreconciled | Versioned procedure lookup/update and actual consumers |
| 16 | LangMem | Source excerpts, §§23–24 | Selected executor and prompt-memory path, not all backends |
| 17 | Current Letta Code | Source excerpts, §29 | Full automatic/server reflection and replay remain unqualified |
| 18 | Archived Letta V1 | Unreconciled | Historical scope remains separate from D17 |
| 19 | Nocturne Memory | Source excerpts, §28 | Read/alias/version mechanisms; do not import persona or boot doctrine |
| 20 | Mem0 OSS | Source excerpts, §31 | Synchronous extraction/formatter; async, full retrieval and hosted platform not qualified |
| 21 | Historical OpenMemory MCP | Unreconciled | Exact historical product and consumer |
| 22 | OpenMemory session CLI | Unreconciled | Real import/export/session path versus roadmap |
| 23 | Cavira LongMemory | Unreconciled | Supersession/decay/checkpoint behavior; distinguish product identities |
| 24 | ripgrep | Unreconciled | Choose concrete source-span use; whole-tool source audit is not necessary |
| 25 | ast-grep | Unreconciled | Specific structural queries and source coordinates for project understanding |
| 26 | SCIP | Unreconciled | Actual producer/version/encoding and definition-reference integration |
| 27 | GitHub Copilot Memory | Unreconciled | Publicly supportable citation/reuse behavior, not an assumed open runtime |
| 28 | Docling | Unreconciled | Relevant document ingestion needs before selecting a parser |
| 29 | Docling Core | Unreconciled | Hierarchy/provenance for the chosen document path |
| 30 | DocETL | Unreconciled | Useful transformation/error handling without importing its runtime |
| 31 | Vector / VRL | Unreconciled | Concrete transform-preservation mechanism; no DSL by default |
| 32 | Kreuzberg v4 LTS | Unreconciled | Exact branch and required native extraction behavior |
| 33 | Current Kreuzberg | Unreconciled | Do not inherit D32's properties by name |
| 34 | Cedar | Unreconciled | No current baseline need for a policy engine; omission is not source review |
| 35 | OPA | Unreconciled | Same: do not add a second policy owner just to use a donor |
| 36 | redb | Unreconciled | Historical recovery ideas only unless a concrete need changes the one-DB choice |
| 37 | duroxide | Unreconciled | Activity identity may be useful; workflow runtime is not selected |
| 38 | Flawless | Unreconciled | Unknown external outcome/retry distinctions |
| 39 | FoundationDB testing | Unreconciled | Not a prerequisite to design or build V3; no new testing platform |
| 40 | Wasmtime | Unreconciled | Only a real extension/isolation need could justify it |
| 41 | SurrealDB Agent Memory / Spectron | Docs/paper | Application-tier descriptions are not a code/runtime audit; native DB is a separate dependency |
| 42 | MAGMA | Source excerpts, §29 | Actual query path inspected, broader ingestion/callers remain partial |
| 43 | A-MEM | Source excerpts, §28 | Library, research implementation and paper must remain distinct |
| 44 | Harness2 | Source excerpts, §§19,25 | Remaining pool/mission/benchmark adapters; no reproduced experiment |

Hy-Memory has extensive selected source findings outside this D numbering. V1 and V2 are also donors outside the external D tally. None was read entirely. The old 43 D + 27 P + 187 S = 257-row inventory is inherited from the supplied/previous audits, not a fresh parsing of the release archive in this pass. It is not 257 distinct software projects or 257 verified experiments.

## 3. The source list is larger than D01–D44

The supplied **`eliot-documentation-audit(1)(1).md`, revision 4, §10.2** explicitly includes material omitted from the maintained D table. Its §§15 and 17 rely on some of those mechanisms. These omissions prevent using D01–D44 as the complete denominator for the owner's request.

| Additional named material | Current status / why it matters |
|---|---|
| claude-mem | Proposed host capture, context reveal and handoff mechanisms have not received a comparable first-hand code pass in the maintained V3 audit. High relevance to the unfinished host-to-memory path. The supplied audit's dated description is not a current implementation guarantee. |
| OpenHands / software-agent-sdk | Supplied audit proposes preserving tool-call/result pairs when cutting context. Exact algorithm and caller still need review before transfer. |
| mcp-memory-service | Supplied audit proposes natural memory triggers; actual current producer/consumer not reconciled. |
| basic-memory | Mentioned as a contrasting Markdown-source design, not selected as Eliot's storage. Source review remains open; no need to import its topology. |
| codebase-memory-mcp | Named external structural source for project understanding. Need one concrete integration choice, not a new embedded code graph. |
| Codex hooks and OpenCode plugins | Additional host surfaces, not interchangeable with Claude hooks by similar event names. First-host work does not qualify them. |
| Surrealist | Existing inspection UI candidate. Choosing an existing tool is different from implementing another operator application. |
| Cloudflare OS, Switchyard, Unsloth, cognee, Perplexity Portable Computer | The supplied audit itself marks these names as requiring clarification/research. Product identity and relevance are not established here. They are not silently accepted dependencies. |

The same section additionally names research families such as MemGPT/HiAgent, Retrieve then Solve, LightMem/MemDelta, STALE/ATMS, Memp/ACON, GraphRAG/CodexGraph/RepoGraph/HippoRAG 2, MemLineage/Selection Integrity/TOKI/MemTX and Meta-Harness. Some overlap old P/S rows. The full deduplicated union has not been established; do not sum names and registry rows as independent coverage. Reading all of them is a research task, not permission to reproduce each framework inside Eliot.

## 4. Audit-of-audits: what is and is not checked

The source filenames below refer to the owner's supplied/Library materials; they are not new files created in this repository. Multiple revisions/copies of one report are not independent corroboration.

| Audit family | Material examined / status | Remaining reconciliation |
|---|---|---|
| Claude documentation audit, revision 4, 2026-10-18 | Previously used throughout V3; this pass rereads donor §10.2 and proposed implementation/original-purpose §§15–17. It reports 968 release files and explicitly limits what was semantically read. | Check remaining recommendations against actual source and the chosen V3 boundary. Its 63-anchor mapping, line budgets, fixed counts and claimed closure are proposals, not implementation evidence. |
| `ELIOT_AUDIT_2026-10-08_v9(1).md` (v8 also located) | Historical base `04eec326...`; this pass reads scope, issue changes, corrections and blocker-map interpretation in §§1–3. | Full T01–T31 and subsequent fixes are not reconciled here. In particular, this report already retracts claims that deferred tests are the established root cause and that a new dependency/status registry is needed. Do not revive those claims. |
| `ELIOT-Swarm-AUDIT-2026-10-06(2).md` | Controller base `40591a2`; introduction and G1/initial G2 read. It spans controller, Memory OS and swarm practice. | Separate historical controller findings from current interfaces and from Memory OS responsibilities. Do not transfer its task-control machinery into memory. |
| `Аудит репозитория eliot-memory-os относительно /docs/architecture` | Base `15d6b40d...`, 2026-08-31; scope, findings and recommendations reread. | Source findings need their version context. The report praised formal routing/proof machinery and proposed additional typed/coverage mechanisms; those recommendations require reconsideration under the explicit lightweight rewrite, not automatic adoption. |
| `Eliot Memory OS: почему проект остаётся незавершённым` | Summary retrieved; no full fresh source reconciliation. | Undated/current-main wording and historical manual-only CI cannot be promoted to present status. |
| `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | Referenced by the supplied Claude audit at §§5,10; complete text not obtained in this pass. | Retrieve the actual report, then compare its recommendations and original donor paths. A citation to it is not a reading of it. |
| Release `audit-2026-10-16-incomplete` | Release metadata and named assets were obtained. Full ZIP bytes and all report bodies were not read in this pass. Earlier selected findings remain in AUDIT. | Reconcile actual audit reports, donor-transfer decisions and research entries. Manifest/coverage/ledger presence is not substantive review of all entries. |
| `audit-2026-09-14.md` | Opening read establishes a Cloudflare/D1 `eliot-research` context, not the Memory OS runtime. | Keep as adjacent-system lessons, not another completed Memory OS audit or evidence about SurrealDB. |

The release contains separately named MANIFEST, execution/intake coverage, blockers, publication and research-join assets. That establishes available artifact names, not that their contents are complete or correct. Archive transfer failed in the available paths; a failed download is not evidence that an asset is missing. No new archive-wide count or completeness percentage is claimed.

## 5. What remains for an implementable V3 model

This is an order of useful design work, not six new subsystems or gates. Each result belongs in the existing Implementation/Cognition text and should remove an ambiguity, not multiply forms.

| Work to finish | Already chosen | Concrete remaining result |
|---|---|---|
| Original-purpose reconciliation | Greenfield local-first memory; original history, cognition, transfer and 29 scenarios retained in grouped form | Compare the remaining V1 Canonical/UL and Architecture requirements with actual mechanisms, especially autonomous understanding, non-code sources, disagreement and self-improvement. Record genuine deliberate departures without claiming every field name implements a capability. |
| Real host/controller boundary | Native first-host events; one existing controller for models and embeddings | One actual host event→saved input example and one supported text request/result plus embedding request/result route, including their real limitations. Select the existing method or name the specific missing implementation in its owner; do not invent another executor. |
| Concrete storage and reads | One SurrealDB Store, primary source preservation, native indexes/relations/transactions | Minimal record layout and representative domain operations: capture with follow-up work, retrieve current and historical material, revise one lesson, load only selected sources. Tie these to a compatible SDK/server choice rather than leaving only logical record-family names. |
| Autonomous work selection and learning | Finite episode work; useful provisional advice; no-change; outcome-linked recursive improvement | Explain what makes work due, which saved episode and prior lessons it reads, what it actually changes, and how the next ordinary context receives it. Separate expensive interpretation from cheap event grouping and from optional evaluation. No worker per cognitive noun. |
| Grounded project understanding | Small purpose/area views and source-linked explanations | Choose a concrete existing structural source for the first path. Connect actual changed resources/consumers to affected views and useful next-action context. Similarity alone is not program structure; source-tool choice is still more specific work than listing ripgrep/ast-grep/SCIP. |
| Practical lifecycle and final consistency | Demand start, usable degraded reads, one observer, simple recovery and direct control | Settle process ownership, specific file/DB recovery choices and first-use configuration; then reconcile Architecture/Implementation/Cognition as one connected design. Windows behavior, performance and quality claims are observed later in implementation, not certified by this map. |

No blanket research completion is required before an unrelated decided component can be implemented after the documentation stage. Conversely, a stack of donor findings does not substitute for the above product decisions. Quantitative effectiveness and a promised fifty-fold reduction cannot be established by reading alone; no test campaign is ordered to compensate for missing design or missing code.

### Current controller boundary rechecked

On controller `main@eeea3558d66a1525c9f5c2d9f3b4f75c62714bf8`, the [README](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/eeea3558d66a1525c9f5c2d9f3b4f75c62714bf8/README.md) and [Memory OS integration document](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/eeea3558d66a1525c9f5c2d9f3b4f75c62714bf8/docs/eliot-memory-os-integration.md) still describe requested, unimplemented runtime integration and preparation-only owner scope. The concrete request documented there is controller→Memory OS context. It is not a reverse text/embedding API contract. A limited `embedding` search mostly found embedding-as-host-composition references; this is not proof that no suitable execution interface exists anywhere. The actual method/caller decision remains open, rather than being treated as solved by that integration filename.

## 6. Next work, without restarting the entire audit

First complete the original-source/audit reconciliation and the real host/controller/Store spine; use claude-mem/OpenHands and the relevant structural-source donor where they answer those gaps. Then settle the learning/refresh policy and finish the remaining practical lifecycle choices. Continue other donor reads against explicit unresolved questions, with a supported decision to use, defer or reject the mechanism. Do not invent a crate or issue for every row.

The former A01–A14 tracks are still represented: requirements/learning; control/notification; process ownership; storage/recovery; retrieval/applicability; producers/consumers; development overhead; own V3 design; Hy coding; Hy transfer; Harness2; donors/archive; interfaces; publication. Their exact earlier inspected ranges remain in the linked maps. In particular, Graphiti temporal filtering, Hindsight complete retain/consolidation, Letta automatic reflection, historical EverMemOS and ORS ownership are still partial—not closed by this census.

## 7. This pass and publication boundary

Fresh work: read the supplied audit's additional donor list and implementation/original-purpose sections; locate and inspect the named historical audit families; distinguish the adjacent Research audit; reread current V3 Architecture, relevant Implementation choices, map/navigation/AGENTS; check current controller README/integration and scoped search. This exposes an incomplete source denominator and explicit design residue. It is not another source audit of all 44 donors.

No product/donor/model/DB run, benchmark, new test program or independent subagent review occurred. Some local execution/asset-transfer paths failed; no local repository checkout or whole-repository diff check is claimed. GitHub compare/ref/readback establish the published change. No audit finding is promoted because a source file was merely located.

This revision changes only the reading map and navigation. Architecture 0.6, Implementation 0.11, Cognition 0.16, consolidated Audit 0.17 and their requirement/scenario tables remain unchanged. Runtime, schemas, dependencies, CI, validators, ACTIVE registry, main and user data are untouched. Product work follows documentation and the owner's product-code/minimum-Clippy/tests-later sequence.
