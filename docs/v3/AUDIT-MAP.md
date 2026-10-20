# V3 audit map

**Revision 0.17 · 2026-10-20.** Reading coverage and next useful action. [AUDIT.md](AUDIT.md) holds findings; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) own mechanisms. This map is not runtime state or an approval gate.

Base: `966650aa71d24cd75a6d214a4f46ab2d832af36a`, PR #5325. V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. This pass follows capture/write/projection and the actual Dreamer model-stage composition, with current D20 Mem0 as a contrasting extraction path. See [Audit §31](AUDIT.md#31-real-interpretation-not-validation-shaped-learning-017). The [0.16 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/966650aa71d24cd75a6d214a4f46ab2d832af36a/docs/v3/AUDIT-MAP.md), [0.15 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/48a622457c826eed3f539d9a870e3521da644527/docs/v3/AUDIT-MAP.md) and [0.14 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT-MAP.md) retain earlier detailed coverage, not new re-reads.

| Track | Covered | Still missing / next connected read | Decision |
|---|---|---|---|
| A01 Purpose/learning | Original 34/29 maps, selected V1/UL/I12, experience/skill consumers; real distinction between projection and interpretation | Original autonomy details and alternative semantic producers | A useful next-action lesson, not a validated empty carrier |
| A02 Control/notification | Broker no-success gate, acknowledgement gap, history/CAS and recurrence; forecast expiry versus completion | Alternative intake and actual delivery feedback | Direct operations; expiry does not resolve a commitment |
| A03 Process ownership | I1.2 and selected lifetime paths; Dreamer actual binary entry | Complete startup/worker registration, generations and recovery callers | One actual observer; a status-only successful exit is not inference |
| A04 Store/recovery | Native Store/SDK/restore/queues; WriterWorker apply/receipt/optional notifier | ORS duties, full primary/purge/backup; all alternative writer compositions | Preserve source first and reuse native transactions |
| A05 Retrieval | Earlier V2 and D01/D03/D08/D09/D10/D19/D42/D43 reads; projection family's actual operations | Graphiti temporal filters, broader donor callers and final Eliot rendering | Working indexing does not establish extracted knowledge |
| A06 Producers/consumers | Observe→writer→projection callback; exhaustive Search/Cue/DependencyDirty/Utility match; Dreamer main→submit and downstream model/material helpers; Mem0 actual add→extraction→persistence | Other V2 semantic scheduling, full MCP registration and actual external controller route | This post-write path is maintenance; the inspected model stage is not inference. Do not generalize to every V2 path |
| A07 Development overhead | Old receipt/CI findings; existing once-call test counts local validation closure | Actual integration resolution, not a new test program | Verify the product operation's meaning; never convert a local validation count into an inference claim |
| A08 Own V3 design | Native connected paths; Audit §31.7 makes saved input→actual model result→ordinary lesson concrete | Implement within existing ownership after documentation | No new proof producer, task fabrication, source-reading certificate or stage manager |
| A09 Hy coding | Prior writer/reconciliation/history/lexical findings | Relevant uncovered source paths | Preserve source and independent retrieval |
| A10 Hy transfer | Prior finite inputs/no-change/compaction findings | Concrete later quality comparison | Similarity is candidate discovery |
| A11 Harness2 D44 | Two loops, selection/reflection/library/ledger/schedule/context/proposer | Remaining pool/mission and benchmark adapters/reset | Existing jobs/controller, real execution contrasts |
| A12 Donors/archive | Fresh D20 Mem0 synchronous extraction; D10/D11 and earlier donor coverage retained | Mem0 async/complete retrieval not reviewed; historical D11/D18 and full archive remain partial | Take actual extraction/batching, not hosted scores or an entire extra runtime |
| A13 Interfaces | Host/DB/OS references, EverOS provider/factory; Dreamer internal cycle distinguished from external controller | Concrete supported controller request/result and installed host event mapping | Material and real response cross the boundary, not only route-shaped DTOs |
| A14 Publication | Existing branch/head and push permission read; prior CI 39442398569 failed on missing PR evidence block | New commit compare/ref/readback and actual workflow status in PR | No inherited PASS, automatic merge claim or gate bypass |

## Fresh source coverage

| Source/version | Actually read in 0.17 | Limit |
|---|---|---|
| V2 `5aac094834fb5635921b550c821cb933a1196105`, capture and writer | `mcp_stdio/verification.rs` 1–260; `writer.rs` 1–320,1000–1340,1570–1840,1910–2470; `cognitive_projection.rs` 1–690 | Source call chain only. Optional projection notifier is not all possible post-commit work; complete MCP startup/worker registration and every alternative scheduler were not read |
| Same V2, Dreamer | `main.rs` 1–230; `lib.rs` 1–240,640–850; `controller.rs` 1–170; `model_stage.rs` 1–540; `admitted_material.rs` 1–555; targeted dispatch usage search | Non-Curation stops before downstream local model/grounding composition. Curation is separate. No live execution or claim that all external model/accounting paths share this behavior |
| D20 Mem0 `0724291bd864cf807e88ee8981c8226644e8fb42` | README45–135; `mem0/memory/main.py` 1–250,480–1120,1170–1255; `utils.py` 1–130 | Synchronous Memory.add and its formatter, not the entire AsyncMemory/backend/hosted platform. The selected source excludes tool-role text from extraction; other host preprocessing may differ |

The writer's real notifier reaches a coordinator that updates search, cues and dependency state; no interpreter is present in that exhaustive family dispatch. This narrows the formerly open edge without proving global absence of every automatic producer.

The inspected Dreamer production model-stage closure validates and hashes a locally constructed empty draft. Its bundle contains handles/omissions rather than loaded episode content, and a text helper returns the question as its hypothesis. A05 usage derived from limits and blanket preservation flags are not observed semantic work. Counterchecks matter: earlier refusal prevents this normal submitted route from reaching those helpers, Partial/candidate-only flags exist, and a separate route-usage call records zero provider calls.

Mem0 actually invokes its configured LLM over new text/recent context/existing memories and batches persistence. Provider exceptions are raised; parse failure still becomes an empty returned extraction. The infer=false path remains embedding-dependent. Useful extraction code does not provide a raw-first guarantee or substitute for coding tool-result capture.

## Prior reads retained

D10 current EverOS `c4a20a28` and D11 historical paper were distinguished in 0.16: default-off foresight, standard search consumer, eligible-corpus hydration, final evidence packing and foreground capacity. D42 MAGMA's query/adaptive/neighbor/packing and D17 Letta's real local compaction versus reflection preparation remain the 0.15 findings. D01/D03/D08/D09/D16/D19/D43 ranges remain in earlier maps and the maintained audit. None is silently promoted to complete review by this pass.

## Transfer and verification limits

Local downloads did not provide a current checkout. Attempting to materialize a GitHub response through Files also failed because that connector response is not a Files attachment; no successful transfer or local diff-check is claimed. Further editing/publication uses GitHub objects directly rather than repeating the failed download. Large source results were expanded where needed; uncovered file ranges remain uncovered.

No product, provider/model, donor, database, Rust/Clippy or synthetic behavior test ran. Existing test source was read to determine what its counter measures, not executed or extended. No independent subagent review occurred. The paper/README performance of a managed service is not measured OSS or Eliot performance.

## Next connected reads

1. Identify the actual external controller inference request/result used by an existing real caller, and compare its input content with the available saved episode. An internal `controller.rs`, a `ModelRouteRequest` or a status receipt is not enough. Record any remaining installed/API gap without building another executor.
2. Read other V2 semantic producers and complete startup registration only where needed to determine whether there is an alternative real learning path. The tested writer→projection route is already understood; do not repeat it as fresh evidence or claim whole-repo absence.
3. Return to original autonomy/understanding and ORS/process ownership where they affect the chosen connected V3 path. A useful observation and a provisional lesson remain available before optional analysis finishes.
4. Finish D08 temporal filters/add_episode and D09 commit-to-consolidation where a stronger donor claim is necessary. Mem0 AsyncMemory, Letta full automatic reflection and historical EverMemOS runtime remain explicit partial coverage, not prerequisites to implement the selected simple mechanisms.

## Preservation

Revision 0.17 adds Audit §31 and updates its header/source/D20 navigation. It does not repeat 0.15's editorial consolidation. The 34 requirements, 29 A15 cases, D01–D44 and all prior audit sections remain; the 36 cognitive walkthroughs are unchanged. Architecture 0.6, Implementation 0.11 and Cognition 0.16 remain unchanged because the new evidence applies their existing connected-path design rather than requiring another rule family.

Runtime, schema, dependencies, CI, validators, ACTIVE registry, main and user data are untouched. Actual changed paths, commit and workflow result belong in the PR. Product work still follows documentation and the owner's product-code/minimum-Clippy/tests-later sequence.
