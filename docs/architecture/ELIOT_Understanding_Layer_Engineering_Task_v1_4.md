# ELIOT Understanding Layer
## Engineering work package UL v1.4 — cognitive functions and system-level project understanding

**Date:** 2026-07-19 (v1.0); amended 2026-07-19 (v1.1 audit alignment); amended 2026-07-20 (v1.2 autonomy + execution protocol); amended 2026-07-20 (v1.3 item-level plan, Part D); amended 2026-07-20 (v1.4 agent surface: plugin + skills, Part E)
**Status:** implementation task; final for UL v1.1
**Relationship:** extends `ELIOT_Canonical_Master.md` and `ELIOT_Rust_Governor_Production_Architecture_v1_0.md`. Nothing here overrides Governor authority, storage topology, write path, tool-surface rules or no-go gates. Where this document is silent, the two canon documents apply unchanged.
**Audit inputs (v1.1):** `AUDIT_MEMORY_OS_2026-07-19.md` and `AUDIT_REMEDIATION_PLAN_2026-07-19.md` are normative inputs. **Part B of this document aligns Part A with the implemented system; where Part B conflicts with Part A, Part B wins.** Parts C, D and E share Part B precedence; where D/E fix a choice Part A left open (incl. Part A WP7 skill wording and B7 skill line), D/E win. v1.2 removes all blocking human approvals: deterministic validation gates replace them (Part C, C1).
**Implementer:** OpenAI Codex, under Governor contract and the project's phase discipline. Section 26.3 of the Rust Governor document (decision rights) applies to this package verbatim.
**Language of record:** English. All identifiers, table names and enum values are normative.

---

# 0. Mission

## 0.1. What this package adds

Governor v1.0 already gives the agent governed memory, current truth, gates and proof. It does not yet give the agent **system-level understanding of a project** — the ability to see the project as a whole working system (purpose, boundaries, causal links, invariants, good and bad decisions) rather than as a sequence of symbols — and it does not solve the **retrieval paradox**: the agent cannot query for knowledge it does not know it needs, and it economizes tokens, so voluntary recall does not happen.

UL v1.0 closes both gaps with seven connected capabilities:

```text
1. Cue binding        — every durable memory is written with world-state triggers.
2. Cue index + push   — memory fires deterministically when the agent touches the world,
                        not when the agent asks.
3. Behavioral graph   — hidden coupling and hotspots mined from Git history.
4. Concept layer      — a small persistent ontology (charter / map / capsules / cards)
                        maintained as a build artifact over the code.
5. Injection map      — hooks place the right slice of understanding into the context
                        window before the agent can act without it.
6. Token ledger       — injection is accepted only if it is token-negative
                        (replaces exploration, never adds to it).
7. Prediction loop    — understanding is measured by calibrated prediction of
                        verifier outcomes, per subsystem, continuously.
```

## 0.2. Theory in one page (binding rationale)

Read this before implementing anything. Every design rule below follows from it.

**Understanding is reconstruction, not storage.** The model understands only inside its context window and forgets on exit. Therefore we do not store "understanding"; we store the materials for its cheap reconstruction. The single quality metric of the whole memory system is **reconstruction cost**: how many tokens a cold model needs to reach competent action.

**The retrieval paradox is structural.** The agent cannot query for (a) unknown unknowns, (b) knowledge whose need it has not yet recognized, and (c) it has no reliable internal "I don't know this" signal. Pull-based memory therefore fails by construction. The fix is to change the addressing scheme: **memory is addressed by world state, not by semantic query.** Each record carries concrete triggers (file paths, symbols, error signatures, commands). Reading becomes deterministic matching: the agent touched file X → records bound to X fire. The agent's actions *are* the query.

**Intelligence at write time, determinism at read time.** At write time the context is hot and already paid for — the writer knows what happened, why, and when it will matter again. At read time the context is cold and every token is marginal cost. Therefore all semantic work (claim extraction, trigger binding, rationale, capsule text) is done at write time and in sleep jobs; the read path is lookup and arithmetic only. Governor never thinks; Governor requires, matches, invalidates and counts. That is enough.

**The whole-system view is a pyramid, not a dump.** Charter (~200 tokens, always present) → System map (~600) → Subsystem capsules (300–500 each) → Module cards (~200) → the code itself. Each level answers four questions: why does this exist, what must stay true, what breaks if violated, where is the proof. "Seeing the whole system" = charter + map + the relevant capsule slice ≈ 1.5–2k tokens, never the whole tree.

**Three graphs carry the "essence and links".** Static (imports/calls, already owned by CodeCortex adapters), behavioral (co-change and hotspots from Git — hidden coupling invisible to static analysis, computed deterministically), causal (the agent's own episodes: change X broke test Y, failure fingerprints, decisions with rationale). Valence ("good and bad decisions") comes from outcomes plus hotspot metrics. **Rationale is ephemeral**: "why" exists only at decision time; either the write path captures it then, or it is lost forever.

**The only guaranteed interface with an LLM is the context window.** Injection equals usage by construction; a tool that can be skipped will be skipped. Hooks turn the loop into a habitat. Injection must be **token-negative**: 2k tokens of pyramid must replace 10–30k tokens of cold self-orientation, or the packet is bad.

**Metacognition lives outside the model.** Coverage, novelty and danger are computed deterministically by Governor and injected. **Understanding is measured by prediction**: every material action carries an expected observation; Governor scores it against the verifier verdict and keeps per-subsystem calibration. Predicting what the system will do under intervention is the only non-fakeable metric of understanding.

## 0.3. Non-goals

Do not implement in UL v1.0:

```text
vector embeddings or a vector index (exact-first remains the law);
a second database or a second canonical memory owner;
new hot MCP tools (the eight-tool rule stands);
autonomous background LLM loops inside the daemon;
changes to the authority model, risk tiers, leases or FinishGate;
whole-repo symbol mirroring into SurrealDB;
natural-language memory search as a primary path;
any change to redb's role (control WAL only, never semantic memory).
```

## 0.4. Vocabulary

```text
cue            — a normalized world-state key (path, symbol, error signature, command,
                 dependency name, task-class tag) that can be observed in tool traffic.
cue binding    — the set of cues attached to a durable record at write time.
firing         — deterministic match of current tool activity against the cue index.
activation     — graph-spread relevance score seeded by fired cues.
concept node   — a named element of the project ontology with purpose and invariants.
capsule        — a bounded prose+handles artifact describing one subsystem, compiled
                 from anchored sources, with a dependency set and dirty tracking.
injection      — Governor-initiated placement of items into the agent context via
                 hook additional-context or packet sections.
token-negative — an injection whose measured token cost is lower than the exploration
                 tokens it replaces.
prediction     — a machine-checkable expected observation attached to an action/probe.
calibration    — statistical agreement between predictions and verifier verdicts.
```

---

# 1. Normative principles

These are enforceable rules. Violating any of them is an architecture deviation and requires an ADR per Rust doc §26.3.

```text
P1  Reconstruction metric. Every UL feature must reduce cold-start reconstruction
    cost or improve prediction calibration. A feature that does neither is rejected.

P2  Mandatory cue binding. A MemoryWriteEnvelope carrying a durable cognitive kind
    (claim, decision, failure_fingerprint, skill, capsule, invariant, episode summary)
    is REJECTED by schema validation if it has no cue_bindings. No exceptions.

P3  Push over pull. The read path for understanding is Governor-initiated injection
    driven by fired cues and hook events. eliot.recall remains available but is a
    secondary, explicitly-expanded surface. No design may depend on the agent
    "remembering to query".

P4  Write-time intelligence, read-time determinism. Model calls (ReasoningJob) are
    allowed only at write time, in sleep jobs, in onboarding and in exams. The hot
    read path (PreToolUse, packet compile, firing, activation) contains zero model
    calls. This restates Rust doc §19.1 ("no direct model calls in gates") and
    extends it to all UL read surfaces.

P5  Small persistent ontology. The concept layer is canonical memory (SurrealDB),
    scoped per project, and hard-capped: charter <= 200 tokens, system map <= 600,
    capsule <= 500, module card <= 200. Budget overruns fail the capsule build.

P6  Capsules are build artifacts. Every capsule declares its dependency set
    (files, claims, edges). A change in a dependency marks the capsule dirty.
    Dirty capsules are recompiled in sleep, never silently served as fresh
    without a dirty flag visible to the reader.

P7  Rationale at decision time. Decision writes without why/alternatives/revisit
    conditions are accepted only as taint=degraded_rationale and are excluded from
    capsule compilation inputs. The write path must ask for rationale exactly once.

P8  Token negativity. Injection volume is metered. The token ledger must show,
    per task family, median net_token_delta <= 0 within two calendar weeks of
    enabling injection for that family, or injection for that family is
    automatically downgraded to handles-only.

P9  Handles before payloads. Default injection form is a one-line annotation plus
    a resource handle. Full payloads are injected only for items whose rendered
    size <= 400 tokens AND whose fired cue is exact (not activation-spread).

P10 Delta over rebuild. Within one task, packets and injections are delta updates
    keyed by revision; an item already injected in the session is never re-injected
    unless invalidated. injection_receipt is the dedup ledger.

P11 External metacognition. Coverage, novelty and danger are computed by Governor
    from counts and graph measures, never by asking the model whether it knows.

P12 Prediction is the exam. Every R1+ action and every probe must carry
    expected_observation (already required by ProbeEnvelope / UnderstandingProof);
    UL adds deterministic scoring and per-subsystem calibration. No new burden on
    the agent beyond what canon already requires.

P13 Canon compliance. All writes go through MemoryWriteEnvelope and writer lanes.
    All new tables are SCHEMAFULL with the mandatory field set of Rust doc §7.3.
    All model outputs are candidate_only until deterministic validation. The
    eight-hot-tool rule, payload budgets and hook latency budgets are unchanged.
```

---

# 2. Canonical data model additions

All tables below live in SurrealDB under the existing namespace, carry the full mandatory field set of Rust doc §7.3 (id, project_id, scope, branch, commit, environment, tri-temporal fields, status, authority, taint, lifecycle_status, visibility, source_refs, evidence_refs, verification_refs, supersedes_refs, policy_version, schema_version), and are written only through the canonical write path. Field lists below show only UL-specific payload fields.

## 2.1. `CueBinding` — extension of `MemoryWriteEnvelope`

Add to `MemoryWriteEnvelope` (Rust doc §8.3) a required field for durable cognitive kinds:

```yaml
cue_bindings:
  - cue_kind: file_path | dir_path | symbol | error_signature | command_pattern |
              dependency | api_surface | task_class | subsystem | concept
    cue_value:            # normalized, see 2.2
    match_mode: exact | prefix | signature
    strength: primary | secondary     # primary = author expects direct reuse here
    expected_reuse_note:  # optional free text; no architecture-level 200-character cap
```

Validation rules (deterministic, in `WriteAdmissionService`):

```text
- durable cognitive kinds require >= 1 primary binding;
- file_path/dir_path values must resolve against the project root at write time
  (missing path => binding accepted with taint=unresolved_path, envelope not rejected,
  because files may be deleted later; but at least one binding must resolve);
- symbol values must be verifiable via CodeGraphAdapter/LSP when adapters are
  available; unverifiable symbols get taint=unverified_symbol;
- error_signature values must be produced by DiagnosticNormalizer's canonical
  signature function (see 2.2), never free-form model text;
- max 12 bindings per envelope; more is a write-time smell and is truncated
  with a receipt note.
```

## 2.2. Cue normalization (single shared function)

Implement one pure function set in `eliot-types` used by writer, matcher and index:

```text
normalize_path(p)        -> canonical, case-folded on Windows, project-relative;
normalize_symbol(s)      -> language-aware "container::name" form from CodeGraph;
error_signature(diag)    -> BLAKE3 over (tool_id, rule_id, normalized_message_class,
                            path_class) — reuse DiagnosticEvent dedup components,
                            but EXCLUDE commit/config_hash so signatures survive
                            rebases and recur across time;
command_pattern(cmd)     -> argv[0] + stable subcommand tokens, flags stripped;
task_class(contract)     -> deterministic classifier over TaskContract fields
                            (edit_kind × subsystem × artifact_kind), enum-valued.
```

The same functions run on the write side (binding) and the read side (firing). Any asymmetry between the two is a bug class; add a property test that write-side and read-side normalization are identical functions, not copies.

## 2.3. Concept layer tables

### `concept_node`

```yaml
concept_node:
  concept_id:
  name:                    # ubiquitous-language term, unique per project
  kind: domain_concept | subsystem | mechanism | policy | external_dependency
  purpose:                 # <= 240 chars, teleology: why this exists
  invariant_refs:          # -> invariant_card ids (existing object)
  valence:                 # yaml: { health: good | mixed | dragon,
                           #         basis_refs: [hotspot_score/failure/decision ids] }
  parent_concept_id:       # optional, forms the concept tree
  entrypoint_refs:         # evidence_atom ids for the 1-3 canonical entrypoints
```

### Relations (add to §7.2 relation set, same edge discipline)

```text
concept_implemented_by:  concept_node -> evidence_atom | module (file/dir anchor)
concept_depends_on:      concept_node -> concept_node   (with reason field)
capsule_covers:          subsystem_capsule -> concept_node
card_covers:             module_card -> file path anchor (evidence_atom)
co_change:               file anchor -> file anchor      (see 2.5)
derived_from stays as-is for capsule -> source provenance.
```

### `project_charter`

```yaml
project_charter:
  charter_id:
  body_md:                 # <= 200 tokens, structure fixed:
                           # WHAT (1-2 sentences) / FOR WHOM / TOP INVARIANTS (3-5)
                           # / NON-GOALS (2-3) / VOCABULARY (5-10 terms)
  concept_refs:
  promotion: auto | human_superseded   # auto on deterministic validation (C1)
  build_id:                # -> capsule_build
```

### `system_map`

```yaml
system_map:
  map_id:
  body_md:                 # <= 600 tokens: subsystems, one-line purpose each,
                           # main data/control flows, external boundaries
  subsystem_concept_refs:
  flow_edges:              # [{from_concept, to_concept, flow_kind, evidence_ref}]
  promotion: auto | human_superseded
  build_id:
```

### `subsystem_capsule`

```yaml
subsystem_capsule:
  capsule_id:
  concept_id:              # the subsystem it covers
  body_md:                 # <= 500 tokens, fixed sections:
                           # PURPOSE / BOUNDARIES / KEY ENTRYPOINTS (with anchors)
                           # / INVARIANTS / DRAGONS (known dangers, with refs)
                           # / KEY DECISIONS (with decision_note refs) / VERIFIERS
  dependency_manifest:     # see 2.4
  dirty:                   # bool + dirty_reasons[]
  build_id:
  freshness_scope:         # branch + commit + adapter versions, like CodeCortexReport
```

### `module_card`

```yaml
module_card:
  card_id:
  path_anchor:             # file or directory evidence anchor
  parent_capsule_id:
  body_md:                 # <= 200 tokens: what it does, who calls it, what it
                           # must not break, verifier handle
  dependency_manifest:
  dirty:
  build_id:
```

### `capsule_build`

```yaml
capsule_build:
  build_id:
  target_kind: charter | map | capsule | card
  target_id:
  inputs_manifest:         # exact source refs: files@commit, claims, decisions,
                           # co_change edges, hotspot scores, CodeCortexReport ids
  reasoning_job_ref:       # the ReasoningJob that produced body candidates
  anchor_validation:       # deterministic result: all cited anchors exist & resolve
  budget_check:            # token count vs cap
  promotion:               # auto | controller_approved | human_approved | rejected
  previous_build_id:       # supersession chain
```

## 2.4. `dependency_manifest` (shared shape)

```yaml
dependency_manifest:
  file_deps:               # [{path, commit_or_checksum}]
  claim_deps:              # claim_card ids
  decision_deps:           # decision_note ids
  edge_deps:               # co_change / concept edges with revision
  report_deps:             # code_cortex_report ids
  invalidation_rule: any_dep_changed
```

Dirty marking is driven from the transactional outbox (Rust doc §7.7): the OutboxDispatcher already publishes committed mutations; a UL subscriber maps changed paths/records to dependent capsules via a reverse index `dep_reverse_index(dep_key -> [capsule_id])` maintained as a derived table.

## 2.5. Behavioral graph tables

### `co_change` (relation)

```yaml
co_change:                 # file_anchor -> file_anchor, undirected semantics,
                           # store once with canonical (min,max) ordering
  support:                 # number of commits where both changed
  confidence_ab:           # P(b changed | a changed)
  confidence_ba:
  last_cochange_at:
  window:                  # mining config snapshot ref
  static_edge_exists:      # bool — is there ANY static edge between them
```

The interesting edges are those with `static_edge_exists=false` and high confidence: hidden coupling.

### `hotspot_score`

```yaml
hotspot_score:
  path_anchor:
  churn_decayed:           # commit-touch count, exponential half-life 90 days
  bugfix_density:          # share of touching commits classified as fixes
  failure_density:         # count of failure_fingerprints anchored to this path
  complexity_hint:         # optional: LOC or indentation proxy from adapter
  score:                   # normalized 0..100, formula in WP4
  computed_at:
  mining_run_ref:
```

### `mining_run`

```yaml
mining_run:
  run_id:
  repo_head_commit:
  window_config:           # since, grouping rule, thresholds, fix-classifier version
  commits_scanned:
  edges_written:
  duration_ms:
```

## 2.6. Rationale extension of `decision_note`

Extend the existing `decision_note` payload (do not create a new table):

```yaml
decision_note (added fields):
  rationale:
    chosen_because:        # <= 300 chars
    alternatives:          # [{option, rejected_because}] 0..4
    revisit_when:          # concrete condition, e.g. "if dependency X > v3"
    confidence: low | medium | high
  rationale_taint: full | degraded_rationale   # degraded when fields absent
```

## 2.7. Prediction and calibration

### `prediction_record`

```yaml
prediction_record:
  prediction_id:
  source_kind: understanding_proof | probe_envelope | exam
  source_ref:
  subsystem_concept_id:    # resolved from write-set/paths via concept graph
  predicted:               # machine-checkable form, one of:
                           #  verifier_verdict { verifier_ref, expect: pass|fail }
                           #  diagnostic_delta { signature, expect: appears|disappears|unchanged }
                           #  blast_radius { predicted_paths[], predicted_failing_verifiers[] }
                           #  observable_value { probe_ref, expected_excerpt_or_range }
  resolved:                # filled by matcher: actual, verdict: hit|miss|partial|unresolvable
  resolved_by_ref:         # verification_run / diagnostic_event / tool_observation
  scored_at:
```

### `calibration_score`

```yaml
calibration_score:
  subsystem_concept_id:
  window:                  # rolling 30d and lifetime rows
  n_predictions:
  hit_rate:
  brier:                   # for probabilistic predictions when confidence given
  blast_precision:         # predicted-and-failed / predicted
  blast_recall:            # predicted-and-failed / all-failed
  trend:                   # improving | flat | degrading (deterministic slope test)
```

## 2.8. Metacognition views (derived, recomputed, cheap)

```yaml
coverage_map:              # per subsystem_concept: capsule_fresh?, card_count,
                           # claim_count, decision_count, episode_count,
                           # coverage_class: covered | thin | blind

novelty_flag:              # per task: touched entities with zero episodes/claims,
                           # nearest covered neighbor concept, suggested first probes

danger_zone:               # per path/subsystem: hotspot_score >= threshold OR
                           # failure_density >= threshold; carries top fingerprints
```

These are projections; they may be cached in Governor memory and persisted as derived tables. They are never authored by a model.

## 2.9. Injection ledger

### `injection_receipt` (specialization of `context_cargo_receipt`)

```yaml
injection_receipt:
  injection_id:
  session_id:
  task_id:
  hook_or_surface: session_start | prompt_submit | pretool | posttool_error |
                   packet_section | precompact
  item_ref:
  render_form: payload | handle
  fired_cues:              # exact cues that matched
  activation_trace_ref:    # when included via spreading
  token_cost:
  outcome:                 # later: used_and_changed_action | used_for_verification |
                           # seen_not_used | expanded_by_agent | invalidated
```

### `activation_trace`

```yaml
activation_trace:
  trace_id:
  seed_cues:
  spread_params:           # depth, decay, caps — config snapshot
  activated:               # [{node_ref, score, path}] top-N only
  suppressed:              # [{node_ref, reason}]
```

## 2.10. `cue_index` (derived projection, hot)

Not a canonical truth table — a derived, rebuildable projection:

```text
cue_index rows: (project_id, cue_kind, cue_value_norm, match_mode)
                -> [ {record_ref, record_kind, strength, freshness_class,
                      negative_memory: bool, token_estimate} ]
```

Storage: persisted in SurrealDB as a derived table for restart recovery; mirrored in Governor memory as an immutable-swap `HashMap`/`fst` per project for O(1)/prefix lookup. Rebuilt from canonical records on startup; incrementally updated from the outbox. **redb is not used for this** (control WAL only — hard rule).

## 2.11. Index additions (extend Rust doc §7.4)

```text
cue_index(project_id, cue_kind, cue_value_norm)
co_change(project_id, path_a)  and (project_id, path_b)
hotspot_score(project_id, score DESC)
concept_node(project_id, name) UNIQUE
subsystem_capsule(project_id, concept_id, lifecycle_status)
module_card(project_id, path_anchor)
prediction_record(subsystem_concept_id, scored_at)
injection_receipt(session_id, item_ref)
dep_reverse_index(project_id, dep_key)
```

---

# 3. Work packages

Each work package (WP) states: goal, owner crate/service, algorithm, integration points, performance budget, acceptance tests, forbidden shortcuts. Implement in the order given in section 6. Every WP ends with real tests against a real SurrealDB service (no mock storage — canon rule).

---

## WP1 — Cue binding on the write path

**Goal:** no durable cognitive memory exists without world-state triggers.

**Owner:** `eliot-engine::WriteAdmissionService` (extension), `eliot-types` (schemas, normalizers).

**Changes:**

```text
1. Add cue_bindings to MemoryWriteEnvelope; bump envelope schema_version.
2. Implement the normalizer set of §2.2 in eliot-types with property tests.
3. Admission algorithm (Rust doc §8.4) gains step: validate_cue_bindings
   BEFORE staging. Rejection error code: CUE_BINDING_REQUIRED (add to §13.12 set).
4. Path resolution uses the project root from scope_state; symbol verification
   calls CodeGraphAdapter with a 50 ms budget and degrades to
   taint=unverified_symbol on timeout (never blocks the write on adapter latency).
5. eliot.record input schema surfaces cue_bindings so the writing agent supplies
   them; the four plugin skills are updated (WP7) to demand:
   "state when this will matter again and what will be on screen".
6. Backfill job (one-off, admin CLI): scan existing durable records lacking
   bindings; derive mechanical bindings where possible (paths from evidence
   anchors, signatures from linked diagnostics); everything else is marked
   taint=degraded_cue and EXCLUDED from the cue index. No model calls in backfill.
```

**Acceptance tests:**

```text
T1.1 Envelope of kind=claim without primary binding is rejected with
     CUE_BINDING_REQUIRED and a receipt explaining the rule.
T1.2 Write with a file binding to a real path succeeds; the cue_index projection
     contains the row within 1 outbox dispatch cycle.
T1.3 Property test: normalize_* are identical functions on write and read side
     (same crate item, single definition — test by symbol identity + fuzz).
T1.4 Backfill on a copy of legacy data produces zero model calls (assert via
     ReasoningBroker counter) and a per-record disposition report.
```

**Forbidden:** free-form cue strings bypassing normalizers; model-generated error signatures; making bindings optional "temporarily".

---

## WP2 — Cue index and deterministic firing

**Goal:** the agent's tool traffic is the query. Matching is O(lookup), no model, no scoring search.

**Owner:** new service `eliot-engine::CueIndexService`; hot mirror in daemon memory.

**Data flow:**

```text
build:    canonical records -> cue_index derived table -> in-memory per-project map
update:   outbox event -> incremental upsert/remove -> atomic swap of project shard
consume:  FiringRequest { session_id, task_id, touched: [normalized cues] }
          -> FiringResult { fired: [record_ref + binding meta], misses_counted }
```

**Firing algorithm (pure, deterministic):**

```text
1. Input cues come only from normalizers applied to observed tool traffic
   (PreToolUse tool input paths/symbols; PostToolUse outputs; DiagnosticEvents).
2. exact match on (cue_kind, value); prefix match only for dir_path;
   signature match only for error_signature.
3. Partition hits: negative_memory first (FailureFingerprint, dragons),
   then invariants, then decisions, then claims/episodes, then skills.
4. Apply session dedup: drop items already in injection_receipt for this
   session unless their record was invalidated since injection.
5. Cap: return at most 8 items + overflow count with a resource handle
   eliot://fired/{firing_id} for the full list.
```

**Performance budget:** firing lookup p95 ≤ 3 ms against the in-memory shard; shard swap ≤ 50 ms; memory ≤ 64 MiB per active project shard (measure; if exceeded, move value lists to SurrealDB and keep only keys hot).

**Acceptance tests:**

```text
T2.1 Editing a file bound by 3 records returns exactly those records, negative
     memory first, within budget.
T2.2 A record invalidated (superseded) stops firing within one outbox cycle.
T2.3 Restart: shard rebuild from SurrealDB reproduces identical firing results
     (golden test on a fixture project).
T2.4 Fuzz: no panic and no cross-project leakage on adversarial cue values.
```

**Forbidden:** semantic similarity anywhere in firing; unbounded result lists; reading redb for cue data.

---

## WP3 — Spreading activation

**Goal:** fire not only direct hits but near-certain neighbors (the file's capsule, its hidden co-change partners, invariants of the touched concept) — with arithmetic, not intelligence.

**Owner:** `eliot-engine::ActivationEngine`.

**Graph:** a unified in-memory view over typed edges already in canon plus UL edges:

```text
node kinds: file_anchor, symbol, concept_node, capsule, claim, decision,
            failure_fingerprint, invariant_card, verifier
edge kinds (with fixed weights, config-snapshotted):
  card_covers / capsule_covers        0.9
  concept_implemented_by              0.8
  co_change (confidence >= 0.6)       0.7 * confidence
  depends_on / calls (static)         0.5
  concept_depends_on                  0.6
  supports / verified_by              0.4
```

**Algorithm (ACT-R-inspired, fully deterministic):**

```text
1. Seeds = fired cues' target nodes, activation 1.0.
2. Breadth-first spread: child = parent * edge_weight * global_decay(0.5);
   depth <= 2; fan-out per node <= 20 (take highest-weight edges);
   accumulate max (not sum) per node to avoid popularity explosions.
3. Threshold: keep nodes with activation >= 0.35.
4. Map nodes back to injectable records (capsule for concept, card for file,
   top fingerprints for danger paths).
5. Emit ActivationTrace with kept and suppressed lists.
```

**Placement in the loop:** activation is computed **asynchronously in PostToolUse** (which is already async-after-spool, Rust doc §14.4) and materialized into a per-session `pending_injection` table. **PreToolUse only reads** the prepared table — this is how the 50 ms hook budget is respected.

**Performance budget:** activation compute p95 ≤ 30 ms on a graph of 50k nodes / 200k edges (bench fixture required); `pending_injection` read in PreToolUse p95 ≤ 2 ms.

**Acceptance tests:**

```text
T3.1 Touching file A with co_change(A,B,conf=0.8) and no static A-B edge
     activates B's module_card above threshold; the trace records the path.
T3.2 Depth/fan-out caps hold under a pathological hub node (10k edges).
T3.3 Determinism: identical inputs + config snapshot => byte-identical trace.
```

**Forbidden:** learning weights online; model-in-the-loop; sum-accumulation without caps.

---

## WP4 — Behavioral graph builder (Git mining)

**Goal:** hidden coupling and valence from history — deterministic, cheap, and available before any concept layer exists.

**Owner:** new adapter `eliot-engine::adapters::GitMiningAdapter` + scheduled job `behavioral_mining` in the JobScheduler (§20.10 job contract: idempotency key, lease, deadline, checkpoint, receipt).

**Algorithm:**

```text
1. Enumerate commits since window start (default: 24 months or 5000 commits,
   whichever smaller) on the default branch; group logical changes:
   one commit = one basket; optionally merge same-author baskets within 30 min.
2. Normalize paths; drop generated/vendored paths via project profile globs.
3. Co-change: for each basket, all unordered pairs; count support; compute
   confidence both directions. Persist pairs with support >= 3 AND
   max(confidence) >= 0.5. Mark static_edge_exists by querying CodeGraphAdapter.
4. Fix classification (deterministic v1): commit message regex set
   (fix|bug|hotfix|revert|patch, project-profile extensible) — recorded as
   classifier_version in mining_run. No model classification in v1.
5. Hotspots: churn_decayed = Σ exp(-age_days * ln2 / 90) over touching commits;
   bugfix_density = fixes/touches; failure_density from fingerprints;
   score = 100 * normalize(churn_decayed) * (0.5 + 0.5*bugfix_density)
           boosted +20% if failure_density > 0 (cap 100).
6. Write through canonical envelopes (tool-observation authority, taint=derived);
   supersede previous mining_run edges rather than mutating.
7. Danger zones view refresh.
```

**Schedule:** full run on onboarding; incremental run nightly (only new commits, merge counts); manual `eliot-governor.exe mine git` admin command.

**Performance budget:** full mine of 5000 commits ≤ 5 min, incremental ≤ 20 s; DB writes batched through the project lane without starving interactive writes (background priority — §5.3).

**Acceptance tests:**

```text
T4.1 Fixture repo with a planted hidden pair (always co-committed, no imports)
     yields the co_change edge with static_edge_exists=false.
T4.2 Re-run is idempotent (same head commit => zero new rows, receipt says noop).
T4.3 Hotspot ordering matches hand-computed values on the fixture within ε.
T4.4 Generated/vendored paths excluded per profile.
```

**Forbidden:** mining on every request; unbounded history walk; model-based fix classification in v1; writing edges without provenance/mining_run ref.

---

## WP5 — Concept layer compiler (capsule pipeline)

**Goal:** the pyramid (charter / map / capsules / cards) exists, is anchored, budget-capped, dependency-tracked and recompiled when reality changes.

**Owner:** `eliot-engine::CapsuleCompiler` + sleep-job `capsule_maintenance` + `ReasoningBroker` job kinds.

**New ReasoningJob kinds (all candidate_only, per canon §10.7):**

```text
CharterDraftCandidate
SystemMapDraftCandidate
CapsuleDraftCandidate
ModuleCardDraftCandidate
ConceptExtractionCandidate
```

**Compilation contract per target:**

```text
INPUTS (assembled deterministically by Governor, handles + bounded excerpts):
  for capsule: concept_node, CodeCortexReport slice for its boundary,
  top-N hotspot paths inside boundary, active invariants, decisions with
  full rationale, failure fingerprints, co_change clusters, prior capsule build.
JOB (token-thrifty split, see C2): Governor FIRST fills the deterministic
  sections from data with fixed templates — ENTRYPOINTS (top code-graph
  entrypoints + anchors), INVARIANTS (invariant_card list), DRAGONS
  (fingerprints + hotspots), KEY DECISIONS (decision_note one-liners),
  VERIFIERS (verifier map). The ReasoningJob then writes ONLY the PURPOSE and
  BOUNDARIES sections (<= 120 tokens combined), citing an anchor handle for
  every load-bearing sentence. Style rule in the job prompt: no praise, no
  narrative, only operative statements; exceeding 120 tokens fails validation.
VALIDATION (deterministic, in Governor):
  - token budget (tiktoken-compatible counter pinned by version);
  - every cited handle exists, resolves, and is inside the declared boundary;
  - every DRAGON cites a fingerprint/hotspot/decision ref;
  - every INVARIANT cites an invariant_card;
  - section skeleton complete.
PROMOTION (fully autonomous — C1):
  - module_card: auto-promote when validation passes;
  - subsystem_capsule: auto-promote when validation passes AND all deps fresh;
    with stale deps it is promoted dirty (STALE header) — never blocked;
  - charter, system_map: auto-promote when validation passes; promotion=auto.
    A human may supersede any pyramid artifact later via the normal write path
    (promotion=human_superseded); supersession is an override, never a gate.
SUPERSESSION: new build supersedes previous; previous remains queryable.
```

**Dirty tracking:**

```text
outbox subscriber -> dep_reverse_index lookup -> mark capsule dirty with reason;
dirty capsules are still injectable but MUST render with a visible header line:
  "[STALE since <event>: <reason>] — verify before relying";
capsule_maintenance recompiles dirty targets, oldest-dirty first, bounded batch
(default 5 per sleep run), each as a separate ReasoningJob with its own receipt.
```

**Acceptance tests:**

```text
T5.1 A capsule citing a nonexistent anchor is rejected at validation; the build
     record shows the exact failing handle.
T5.2 Editing a file in a capsule's dependency_manifest marks it dirty within one
     outbox cycle; injection of that capsule renders the STALE header.
T5.3 Budget overrun (501 tokens) fails the build with budget_check details.
T5.4 Charter failing any deterministic check (budget, anchors, skeleton)
     is never promoted; passing one is promoted with promotion=auto and a
     complete capsule_build receipt (no human step in the path).
T5.5 Recompiled capsule preserves section skeleton and supersedes prior build.
```

**Forbidden:** unanchored prose in any pyramid artifact; serving dirty as fresh; model-side self-approval; embedding the whole repo into job inputs (handles + bounded excerpts only, per payload budgets §19.3).

---

## WP6 — Onboarding job (cold repository → concept layer)

**Goal:** bring an existing project from zero to a usable pyramid in one governed offline pass.

**Owner:** `eliot-engine::OnboardingJob` (JobScheduler, admin/controller initiated: `eliot.lifecycle` op `onboard_project` or CLI).

**Pipeline (checkpointed, resumable):**

```text
STAGE 0  preflight: project profile, path globs, verifier map discovery,
         GitStateAdapter snapshot. Receipt.
STAGE 1  WP4 full mining run (deterministic).
STAGE 2  structure scan: CodeCortex boundary pass — directories, manifests,
         load order, entrypoints; NO deep semantic pass yet.
STAGE 3  concept seeding is DETERMINISTIC: candidate boundaries = top-level
         source dirs × mining co-change clusters × manifest units; merge by
         path-overlap >= 0.6; drop boundaries with < 3 files; cap 20, floor 6
         (below floor: use dirs as-is). ONE batched ConceptExtractionCandidate
         job names them and writes purpose lines (<= 30 tokens each) for ALL
         seeds in a single call; names failing uniqueness/length checks fall
         back to the deterministic dir-derived name.
STAGE 4  deterministic acceptance: every source file maps to exactly one
         concept (largest-overlap rule, ties -> parent dir); orphan files go
         to concept `_unassigned`; write acceptance receipt. NO approval step.
         An optional async human review may later rename/split concepts via
         supersession — it never blocks the pipeline.
STAGE 5  per accepted concept: CapsuleDraftCandidate with WP5 validation;
         module cards for top-K hotspot files per subsystem (default K=5).
STAGE 6  SystemMapDraftCandidate from accepted concepts + flow evidence;
         CharterDraftCandidate from map + README/manifest anchors.
         Both auto-promote per WP5 rule; inputs capped at 4 KiB each.
STAGE 7  final report: coverage_map computed; blind zones listed;
         reconstruction-cost baseline measured (see WP8 T8.1 protocol).
```

**Budgets (hard):** ReasoningJobs <= N_subsystems + 3 total (1 batched naming + 1 per capsule + map + charter); each job input <= 4 KiB of excerpts + handles, output schema-bound; wall-clock <= 2 h single worker; all jobs candidate_only. Everything else in the pipeline is deterministic Rust.

**Acceptance tests:**

```text
T6.1 Onboarding the ELIOT Governor repo itself runs with ZERO human input,
     produces >= 6 accepted concepts, capsules for each, charter+map promoted
     auto, and a coverage_map with zero "blind" for eliot-types/store/engine/app.
T6.2 Kill the job at any stage; resume completes without duplicate writes
     (idempotency keys verified in receipts).
T6.3 File-to-concept mapping is total and unique (deterministic acceptance);
     a later human supersession of one concept renames it without re-running
     onboarding and without breaking existing cue bindings.
T6.4 ReasoningJob count == N_subsystems + 3 exactly; every job input <= 4 KiB
     (assert via job receipts).
```

**Forbidden:** any blocking approval step; per-file ReasoningJobs (subsystem granularity only); unbatched naming calls; writing anything as non-candidate before validation.

---

## WP7 — Injection map (hooks + packet integration)

**Goal:** understanding reaches the window before the agent can act without it. The agent never has to remember to ask.

**Owner:** `eliot-engine::InjectionPlanner`; hook handlers of Rust doc §14.4 (extended, not replaced); `ContextCompiler` packet sections.

**Injection map (normative):**

```text
SessionStart        -> charter (payload) + system_map (payload) + coverage note.
                       Budget: <= 1200 tokens total, inside the 8 KiB hook cap.
                       If charter/map missing: inject one line
                       "project not onboarded; run onboarding" — nothing else.

UserPromptSubmit /  -> after TaskContract framing: capsules of subsystems whose
eliot.bootstrap        boundaries intersect scope/allowed_paths (payload, max 3,
                       dirty ones with STALE header) + danger_zone summary for
                       the write-set + novelty_flag if coverage is thin/blind.

PreToolUse          -> read prepared pending_injection for the touched paths:
                       module_card (payload if fresh, else handle),
                       fired negative memory (ALWAYS payload, cap 3),
                       fired invariants (payload one-liners),
                       other fired items as handles. Budget: <= 700 tokens,
                       <= 8 items. Pure lookup — no compute in the hook.

PostToolUse         -> on DiagnosticEvent/test failure: match error_signature
                       against cue index; queue matched episodes/fingerprints
                       into pending_injection for the NEXT PreToolUse and,
                       when severity=error, return a one-line notice now.

PreCompact          -> unchanged canon HandoffArtifact + add: active concept ids,
                       injected-and-used item refs (so resume re-injects only
                       what mattered).

PostCompact         -> resume packet includes charter handle + the used-set from
                       the handoff, NOT a fresh full pyramid (delta principle).

eliot.packet compile-> packet section `causal_understanding.project_capsule`
                       (already in canon skeleton) is now REQUIRED to be the
                       relevant subsystem_capsule refs; section `memory` items
                       must carry fired_cue or activation provenance in the
                       manifest (no unexplained inclusions).
```

**Dedup and delta (P10):** before any injection, check `injection_receipt` for (session_id, item_ref); skip unless invalidated. Within a task, `eliot.packet refresh` returns only changed sections keyed by packet_revision.

**Skill updates (plugin, §14.6):** extend the four skills' text: `eliot-task-cycle` adds "trust injected capsule/card headers; expand handles only when the next action depends on them"; `eliot-code-understanding` adds "if a STALE header is present, verify against code before relying"; recording guidance adds the WP1 reuse question. Skills remain ≤ current size class; no new skills.

**Acceptance tests:**

```text
T7.1 Fresh session on onboarded project: first assistant turn context contains
     charter+map; token count of the injection <= 1200 (assert via receipt).
T7.2 Editing a hotspot file with 2 fingerprints: PreToolUse response contains
     both as payload, ordered before any other item; hook p95 <= 50 ms holds
     under load test (1000 sequential PreToolUse with warm daemon).
T7.3 The same card is not injected twice in one session (receipt-verified),
     but IS re-injected after its capsule is invalidated.
T7.4 A failing test whose signature matches a stored episode causes that episode
     to appear in the next PreToolUse injection.
T7.5 8 KiB hook cap is never exceeded (fuzz with oversized capsules => handles).
```

**Forbidden:** computing activation inside PreToolUse; injecting full capsules on every tool call; any injection without a receipt; increasing hook timeouts to fit more payload.

---

## WP8 — Token ledger and token-negativity enforcement

**Goal:** injection provably reduces total tokens; the agent's own thrift works for the system.

**Owner:** `eliot-engine::TokenLedger` + report job.

**Metering:**

```text
injected_tokens(session/task)     — sum from injection_receipts;
exploration_tokens(task)          — tokens of read-class tool traffic
                                    (file reads, grep, list, LSP queries,
                                    recall expansions) between task start and
                                    first mutating action, plus between a
                                    packet refresh and next mutation;
net_token_delta(task)             = injected − matched_baseline_exploration.
```

**Baseline protocol:** per task_class, maintain a rolling baseline of exploration_tokens from tasks executed with `ul.injection.enabled=false` (config flag). Rollout runs A/B by task parity (even/odd task ordinal per class) for the first two weeks per project, then injection-on becomes default and the baseline freezes (re-baselined quarterly).

**Enforcement (deterministic policy, per P8):** if a task_class shows median net_token_delta > 0 over ≥ 10 tasks, InjectionPlanner automatically downgrades that class to handles-only and opens an incident-class report (`report_manifest`) for tuning. Re-enable requires a config change (operator).

**Acceptance tests:**

```text
T8.1 Reconstruction-cost harness: scripted cold task ("orient and state the
     verifier for change X") measured with and without pyramid; the harness
     is deterministic and reusable (this is also the onboarding STAGE 7 tool).
T8.2 Ledger correctly attributes tool tokens by class on a fixture trace.
T8.3 Forced-positive-delta fixture triggers automatic downgrade and report.
```

**Forbidden:** counting model output tokens as exploration; gaming the baseline by reclassifying tools; silent downgrade without report.

---

## WP9 — Metacognition services (coverage / novelty / danger)

**Goal:** the "I don't know" signal the model lacks, computed outside it.

**Owner:** `eliot-engine::MetacognitionService` (pure functions over counts and graphs) + gate integration.

**Rules:**

```text
coverage_class per subsystem:
  covered: fresh capsule AND (claims+decisions+episodes) >= 5
  thin:    capsule exists but stale OR counts < 5
  blind:   no capsule

CognitiveGate additions (deterministic, extends §10.9 checklist):
  - R2/R3 proof whose write-set touches a BLIND subsystem
      => REQUIRE_PROBE (investigation-first), never silent ALLOW;
  - proof touching a subsystem with a fresh capsule MUST reference each of that
    capsule's invariant_refs in proof.invariants OR list it in an explicit
    `waived_invariants` field with a reason; missing => REQUIRE_PACKET_REFRESH.
    (This is a handle-presence check — cheap, non-semantic, non-theatrical.)

novelty_flag: emitted at framing when >= 30% of touched entities have zero
  episodes/claims; injected as one line + suggested cheapest probes (from
  verifier map), NOT as prose advice.

danger_zone: hotspot score >= 70 OR failure_density >= 2 => PreToolUse renders
  the danger line + top fingerprints before any other injection for that path.
```

**Acceptance tests:**

```text
T9.1 R2 proof into a blind subsystem returns REQUIRE_PROBE with the exact
     subsystem named and a suggested probe.
T9.2 Proof omitting a capsule invariant is bounced with the missing ref id;
     adding it to waived_invariants with a reason passes the check.
T9.3 Coverage_map recomputation is incremental (outbox-driven) and matches a
     full recomputation on the fixture (golden test).
```

**Forbidden:** asking the model to self-assess coverage; free-text gate reasons without record refs; blocking R0/R1 reads on blindness (investigation must stay cheap).

---

## WP10 — Prediction and calibration loop (the exam)

**Goal:** understanding gets a number. The number is per subsystem, trend-tracked, and produced from artifacts the canon already requires.

**Owner:** `eliot-engine::CalibrationService` + `prediction_matcher` outbox subscriber + weekly `understanding_exam` job.

**Capture (no new agent burden):**

```text
On UnderstandingProof acceptance: extract expected_observation and
proposed_write_set => prediction_record(kind=verifier_verdict and/or
blast_radius, subsystem resolved via concept graph).
On ProbeEnvelope execution: expected_observable => prediction_record.
```

**Matching (deterministic):**

```text
verifier_verdict: join on verifier_ref to the VerificationRun produced within
  the same ActionLease/work item; hit iff verdict matches expectation.
diagnostic_delta: compare DiagnosticEvent signature sets before/after the
  action's ToolObservations.
blast_radius: predicted_paths vs (a) actually changed paths from ChangeMonitor
  and (b) verifiers that actually failed => precision/recall.
unresolvable (no verifier ran, lease expired) is recorded as unresolvable,
  never guessed.
```

**Aggregation:** rolling 30d + lifetime `calibration_score` per subsystem; trend by Mann-Kendall or simple regression sign test (deterministic, documented).

**Weekly exam (`understanding_exam` job, candidate_only reporting):**

```text
1. Sample 5 subsystems weighted by (activity × staleness of last exam).
2. For each, generate 3 questions DETERMINISTICALLY from graphs:
   Q-blast: "if <symbol/file> changes, which verifiers fail?"
     ground truth = verifier_map + static/co_change edges, verified where cheap
     by actually running the mapped verifier on a throwaway worktree mutation
     when project policy allows (R-tier rules apply; default: dry, graph-truth).
   Q-invariant: "which invariant protects <path>?" ground truth = concept graph.
   Q-entry: "what is the entrypoint for <concept>?" ground truth = capsule anchors.
3. Ask via ReasoningJob to the controller-route model with ONLY charter+map in
   input (cold-start condition), no capsule for the examined subsystem.
4. Grade deterministically against ground truth; write exam report
   (report_manifest) with per-subsystem scores and deltas vs last week.
5. Low scores (< 0.5) mark the subsystem's capsule dirty with reason
   exam_failure => WP5 recompiles it.
```

**Acceptance tests:**

```text
T10.1 A merged action with a passing predicted verifier yields a hit record
      attributed to the right subsystem.
T10.2 Blast precision/recall computed correctly on a fixture with known
      changed paths and failing verifiers.
T10.3 Exam runs end-to-end on the fixture project, produces a graded report,
      and a planted-bad capsule scores low and is marked dirty.
T10.4 No exam artifact ever mutates current truth, policy or completion
      (assert via write-kind audit — canon dream rules apply).
```

**Forbidden:** model-graded exams; treating unresolvable as miss or hit; rewarding polished explanations (verdict-only grading).

---

# 4. MCP and resource surface changes

No new hot tools. Extend operations and resources only:

```text
eliot.recall     += ops: concept_view (charter/map/capsule/card by id or path),
                        fired (expand a firing_id), why_injected (receipt view).
eliot.packet     += op: delta (changed sections since packet_revision).
eliot.lifecycle  += ops: onboard_project, approve_concepts, approve_pyramid,
                        mine_git (admin/controller profiles only).
resources        += eliot://concept/{id}, eliot://capsule/{id},
                        eliot://fired/{firing_id}, eliot://calibration/{project},
                        eliot://coverage/{project}, eliot://exam/{report_id}.
errors           += CUE_BINDING_REQUIRED, CAPSULE_STALE, NOT_ONBOARDED.
```

All outputs use structuredContent per §13.11; text content stays one-line + resource URI.

---

# 5. Configuration additions (Appendix-A style keys)

```toml
[ul.cue]
max_bindings = 12
symbol_verify_timeout_ms = 50

[ul.activation]
depth = 2
decay = 0.5
fanout_cap = 20
threshold = 0.35

[ul.mining]
window_months = 24
max_commits = 5000
min_support = 3
min_confidence = 0.5
hotspot_halflife_days = 90

[ul.pyramid]
charter_tokens = 200
map_tokens = 600
capsule_tokens = 500
card_tokens = 200
maintenance_batch = 5

[ul.injection]
enabled = true
session_start_budget_tokens = 1200
pretool_budget_tokens = 700
pretool_max_items = 8
payload_max_tokens = 400

[ul.token_ledger]
ab_weeks = 2
downgrade_min_tasks = 10

[ul.exam]
weekly = true
subsystems_per_run = 5
dirty_threshold = 0.5
```

Every value is snapshotted in `config_snapshot` and referenced by traces (determinism requirement).

---

# 6. Implementation order and dependencies

UL slots into the canon phase plan after Phase E (live CodeCortex). WP4 may start after Phase B.

```text
UL-1: WP1 + WP2            (cue write + index + firing)      — depends: Phase B/C
UL-2: WP4                  (behavioral graph)                — depends: Phase B
UL-3: WP3 + WP7-minimal    (activation; PreToolUse negative  — depends: UL-1, D
                            memory + card injection only)
UL-4: WP5 + WP6            (capsules + onboarding)           — depends: E, UL-2
UL-5: WP7-full + WP8       (full injection map + ledger)     — depends: UL-3, UL-4
UL-6: WP9 + WP10           (metacognition + calibration/exam)— depends: UL-5
```

Rule (canon §24.1 spirit): each UL stage ships only against the real SurrealDB service, with receipts, and with its acceptance tests green in CI. No stage may be skipped to "get to the interesting part".

**First-value milestone (explicit):** at the end of UL-3, on one real project, the agent must already receive fired negative memory and module cards on file touch — before any pyramid exists. This is the earliest observable payoff and the go/no-go checkpoint for continuing to UL-4.

---

# 7. Evaluation additions (extends canon §35)

```text
EVAL-CUE      binding coverage: % durable writes with resolving primary cue;
              firing precision: % injections later marked used_* (target: >= 40%
              after 4 weeks; below 25% => tune thresholds, report).
EVAL-CONCEPT  pyramid freshness: % capsules fresh; anchor validity: 100% required;
              exam score trend per subsystem (must not degrade 3 weeks running).
EVAL-TOKENNEG median net_token_delta per task_class (<= 0 required to keep
              payload injection); reconstruction-cost harness delta
              (target: >= 30% reduction vs no-pyramid baseline).
EVAL-CALIB    hit_rate and blast precision/recall per subsystem; global Brier
              trend; % unresolvable (must stay < 30%, else verifier-map gap).
EVAL-REPEAT   (sharpens canon EVAL-NEGATIVE): % file-touches on fingerprinted
              paths where the fingerprint was injected BEFORE the mutating call
              (target: 100% — this is deterministic and must be perfect).
```

Counter-metrics (must be watched, canon discipline): missing-context regret (agent expands handles immediately after injection => payload should have been sent), suffocation (REQUIRE_PROBE rate on blind subsystems > 20% of R2 attempts => onboarding gap), injection fatigue (used_* rate falling over weeks).

---

# 8. Definition of done and no-go gates for UL v1.0

## 8.1. Done only when

```text
1.  A durable cognitive write without a primary cue binding is impossible.
2.  Touching a bound file injects its records within hook budgets, receipts kept.
3.  Co-change and hotspot data exist for the pilot project and are queryable.
4.  Charter, map, capsules and cards exist for the pilot project, all anchors
    valid, budgets enforced, dirty tracking live, STALE rendering visible.
5.  Onboarding runs end-to-end on a second, previously unseen repository with
    zero blocking human steps (deterministic acceptance receipts present).
6.  Session start, framing, PreToolUse, PostToolUse-error, PreCompact and
    packet sections follow the injection map; dedup receipts verified.
7.  Token ledger reports exist; at least one task_class demonstrates measured
    token-negativity; automatic downgrade path tested.
8.  Blind-subsystem R2 proofs are diverted to probes; capsule invariants are
    handle-checked in proofs.
9.  Prediction records accumulate from real work; calibration and weekly exam
    reports render; a planted regression is caught by the exam (T10.3).
10. All new tables SCHEMAFULL, all writes enveloped, all model outputs
    candidate_only, zero model calls on hot read paths (assert by counter).
```

## 8.2. Hard no-go conditions

Do not declare UL v1.0 ready if any is true:

```text
firing or activation calls a model or a network service;
cue normalization differs between write and read side;
redb stores any cue/concept/behavioral data;
a pyramid artifact contains an unresolvable anchor;
charter or system_map exists without an approval record;
injection occurs without a receipt, or the same item repeats in-session;
PreToolUse p95 exceeds canon budget with UL enabled;
hook additional context exceeds 8 KiB in any test;
a task_class runs > 4 weeks with positive median net_token_delta and
  payload injection still enabled;
exam or calibration artifacts mutate truth, policy or completion;
a new hot MCP tool was added.
```

---

# 9. Decision rights for Codex on this package

Codex MAY decide: internal module layout inside the named services; concrete map/fst structures for the hot index; batch sizes within stated budgets; fixture repo contents; report formatting preserving canonical fields; exact regex set for fix classification (recorded as classifier_version).

Codex MAY NOT decide: the injection map; cue kinds and normalization semantics; budgets and thresholds defaults (change via config + ADR only); promotion/approval rules for pyramid artifacts; adding model calls to read paths; edge weights learning; relaxing any no-go gate. Deviations follow canon §26.3: ADR proposal, never silent implementation.

---

# Appendix A. Worked end-to-end scenario (normative illustration)

```text
Day 0   Operator runs onboarding on project P. Mining finds co_change
        (net/session.rs <-> proto/frames.rs, conf 0.82, no static edge).
        14 concept seeds merged to 11 accepted deterministically (zero human
        input). Capsules built; charter+map auto-promoted with receipts.
        Reconstruction baseline recorded: 24k exploration tokens for the
        scripted cold task; with pyramid: 6k. EVAL-TOKENNEG green.

Day 3   Codex gets task "change reconnect backoff". SessionStart injects
        charter+map (1.1k tokens). Framing intersects scope with concept
        `net`; capsule injected; danger line for net/session.rs (hotspot 78,
        2 fingerprints). PreToolUse on opening session.rs fires: FF-112
        ("naive retry loop broke handshake ordering", payload),
        invariant INV-7 one-liner, module card, and — via activation over
        co_change — a handle to proto/frames.rs card.
        UnderstandingProof cites INV-7 (required by WP9), predicts
        verifier net_reconnect_test=pass and blast=[session.rs, frames.rs].
        Verifier passes; frames.rs indeed changed. prediction hit;
        blast precision 1.0. Decision written WITH rationale and cue bindings
        (paths + error signature of the old bug + task_class net_edit).

Day 5   Another session breaks net_reconnect_test. DiagnosticNormalizer emits
        the signature; PostToolUse matches Day-3 episode; next PreToolUse
        injects it. The agent does not re-derive the mechanism from scratch.

Week 2  session.rs edit lands outside the capsule's recorded entrypoints;
        capsule marked dirty; injected with STALE header until sleep
        recompiles it. Weekly exam: subsystem `net` scores 0.9; subsystem
        `storage` scores 0.4 (capsule predates a refactor) => capsule dirty
        (exam_failure), recompiled next sleep. Calibration report shows
        blast recall dip in `storage` the same week — two independent
        signals, one cause, both deterministic.
```

This scenario is the behavior contract. If the implemented system cannot reproduce it on the fixture project, UL v1.0 is not done.

---

# Part B — Audit alignment addendum (v1.1, normative)

Part A was written against the Rust Governor architecture document. The 2026-07-19 audit examined the **implemented** system (135k LoC, 5 crates, live MCPB plugin, SurrealDB 3.1.4 server, phase L14 `ARCHITECTURE_COMPLETE_UNCERTIFIED`). Part B binds Part A to that reality. Precedence: **B over A**; canon guard-list (B5.4) over both.

## B1. Implemented-system snapshot (audit-Verified facts UL relies on)

```text
WORKS (build on it):
  authenticated sessions, honest no_task_role_granted, lease authority model;
  candidate-only writes; promotion only via verifiers; anti-falsification of
    influence (downstream_outcome_ref gate, cognition.rs:300-310);
  revision fences on every response; single WriterActor on bounded mpsc;
  three storage classes live (Surreal server/RocksDB, redb WAL, BlobStore);
  blake3-pinned registered verifiers; clean fmt/check/clippy; crate-boundary
    guard (no surrealdb crate) automated in Justfile;
  L2 fetch cards are rich (negative_constraints, where_applicable, freshness_rule);
  L3 compiler honestly reports insufficiency; causal-bridge hop math is real;
  protected DecisionLocalitySuffix survives budget cuts.

BROKEN OR ABSENT (UL must not assume it):
  P0-1 recall L0 = exact-phrase substring over claim_card only; questions get
       false no_useful_memory; considered/returned funnel is theater;
  P0-2 need-logic circular (unread candidate_handles counted as evidence),
       computed after budget trim, English-only markers, ASCII lowercase;
  P0-3 L3 packet carries handles, never content; memory_mode is a no-op;
  P0-4 language blindness in need heuristics;
  P1-1 observability writes (influence trace) not idempotent, move memory_revision;
  P1-2 at least one host write path destroys Cyrillic (UTF-8 → '?');
  P1-3 published MCP schemas lie vs serde reality (16-field material_frame,
       ~14-field trace discovered by error archaeology);
  P1-4 top-level packet_id overwritten by constant task ref;
  P1-5 duplicates unsuppressed; correction annotations create no edges;
  P1-6 relation graph EMPTY on live paths (0 edges in project memory);
  P1-7 double MCP server registration (global + plugin);
  0 promoted claims in 395 revisions; memory polluted by nonce probes;
  all canonical tables SCHEMALESS (validation Rust-side only);
  eliot-app monoliths: mcp_stdio.rs 33k / commands.rs 19k / host_runtime.rs 7.8k.
```

## B2. Terminology and surface mapping

Part A used architecture-document names. Bind them to the implemented 12-tool MCPB surface **by capability, not by name**. Observed mapping:

| Part A / arch doc | Implemented (observed in audit) |
|---|---|
| `eliot.bootstrap` | composition: `eliot_host_session_status` + `eliot_project_identity` + `eliot_current_state` |
| `eliot.state` | `eliot_current_state` (revision-fenced) |
| `eliot.recall` L0/L2 | `eliot_recall_l0`, `eliot_fetch_l2` |
| `eliot.packet` | `eliot_compile_packet_l3` (+ `material_frame`) |
| `UnderstandingProof` | `MaterialPacketFrame` — 16 fields incl. `expected_observable`, `causal_bridge[{from,to,relation}]`, `negative_memory_checked`, `verifier`, `stop_condition`, `active_plan`, `killed_paths` |
| `ContextCargoReceipt` / influence | `eliot_memory_influence_trace` (`influence_class` enum, `downstream_outcome_ref`) |
| `eliot.record` | `eliot_agent_candidate_submit`, `eliot_write_cognitive_observation` |
| `FinishGate`, `ActionLease`, Codex hook map | **not observed in audit** — bind if present; if absent, UL features that need them degrade per B7, they are NOT re-implemented inside UL |

Rules: (1) the "no new hot tools" law of Part A §4 now reads against the **actual 12-tool surface** — UL adds operations/response fields only; (2) P1-7 dedup (single server registration) is a UL prerequisite; (3) skills are bound by capability too (audit shows `eliot-understanding` naming, not Part A's four-skill naming).

## B3. Prerequisite matrix (remediation plan → UL)

| Remediation item | Blocks | Why |
|---|---|---|
| §1 Librarian (P0-1: tokenized FTS disjunction + threshold) | UL-6 metrics only | cue firing (WP2) is **independent** of recall and works while recall is broken; but utility/calibration statistics are poisoned by false `NO_USEFUL_MEMORY` until fixed — see B10 quarantine |
| §2 need-logic (P0-2/P0-4) | WP8 | token ledger's need/exploration accounting is meaningless while need-decision is circular and trim-order-dependent |
| §3 packet content (P0-3) | WP7 packet-channel, UL-4+ | Part A injects capsules/cards through packet sections; today packets carry no content, so this channel is dead until P0-3 |
| §4.1 observability idempotency (write_id) | WP7 receipts, WP10 | injection_receipt and prediction_record are observability-class; they MUST be idempotent and MUST NOT advance truth revision (or follow the documented single-log decision of §4.1 — but idempotency is non-negotiable) |
| §4.2 schemas from types | WP1, all new UL forms | UL adds envelope fields and tool ops; publishing them with hand-written schemas would reproduce the archaeology disease. schemars-derived schemas + aggregated `-32602` are mandatory for every UL form from day one |
| §4.4 live relation edges | WP3 | activation needs a graph; live graph is empty. WP4 co_change edges + UL's own `belongs_to`/`covers`/`concept_implemented_by` writes provide the first real edge population; §4.4 `supersedes` enables duplicate_penalty |
| §4.5 UTF-8 guard | WP1, WP5 | cue values and capsule bodies must pass the same guard; a corrupted cue never fires, a corrupted capsule poisons every injection |
| §5 monolith decomposition | all UL app-layer code | UL dispatch/schema code goes into the decomposed modules (`mcp_schemas.rs`, `mcp_dispatch_memory.rs`, ToolInput forms in `eliot-types`), **never** into `mcp_stdio.rs` |

## B4. Phase placement

Plain ordering — no committees, no sign-offs inside UL:

```text
1. WP4 Git mining starts IMMEDIATELY and runs autonomously on schedule
   (read-only over Git, canonical envelopes, background priority). It blocks
   nothing and nothing blocks it.
2. Remediation items P0-3, P1-1, P1-3, P1-6(minimal), P1-2-guard are code
   prerequisites for the injection/packet channels (B3). Finish them first
   (they are part of the repo's L15 scope); then execute UL-1..UL-6 in the
   B8 order. "Phase" labels are bookkeeping only.
3. The only hard external budget respected: reserved full-suite starts and
   release counts — UL tests are focused suites and never consume them.
```

## B5. Amendments to Part A principles

**B5.1 (amends P13).** "All new tables SCHEMAFULL" is retargeted: implemented canonical tables are SCHEMALESS with Rust-side validation. New UL tables follow the **stronger** of the two once the project decides schema policy; until then: Rust-side validation from the same `eliot-types` structs that generate published schemas (single source of truth), plus `DEFINE INDEX` entries of Part A §2.11. Do not migrate legacy tables inside UL.

**B5.2 (new P14 — schema truth).** Every UL-visible form (envelope extension, tool op input/output, response block) ships with a schemars-derived published schema generated from the serde type, a roundtrip test (serialize → validate against published schema), and aggregated deserialization errors (one `-32602` listing all missing fields). Raw `-32603 missing field` leaking to an agent is a UL release blocker.

**B5.3 (new P15 — Unicode discipline).** All UL normalization uses Unicode-aware lowercase (`char::to_lowercase` semantics), never `to_ascii_lowercase`; tokenization splits on `!is_alphanumeric`; RU/EN stop-word const lists; the WP2 firing normalizers and the Librarian's `tokenize_query` (remediation §1.4) share one module in `eliot-types` — Part A test T1.3 now also asserts identity with the Librarian path. UL text fields pass the §4.5 UTF-8 guard at admission.

**B5.4 (new P16 — guard list adoption).** Remediation §7 is adopted verbatim as UL law: UL must not weaken anti-falsification (`downstream_outcome_ref`), candidate-only writes and no self-promotion, revision fences, the single writer, the no-surrealdb-crate boundary, Win32 `unsafe` isolation in `eliot-windows-ipc`, phase budgets, or trace determinism.

**B5.5 (amends P8/WP8 experiment arms).** The control arm mechanism is the existing `memory_free_control` packet mode plus `ul.injection.enabled=false`. Coherence rule: when a compile runs in `memory_free_control`, InjectionPlanner suppresses ALL UL injection for that task turn — the control condition must be genuinely memory-free. This also resolves audit P2-4: after P0-3 + UL, control mode becomes measurably different from treatment; add test T-B7 below.

## B6. Amendments per work package

**WP1.** (a) `cue_bindings` lands on the implemented candidate-submit envelope (`eliot_agent_candidate_submit`), schema per B5.2. (b) Reuse/extend the §4.5 UTF-8 guard for cue values; reject `U+FFFD` and `?{3,}`-in-Cyrillic-context. (c) Backfill exclusion list: nonce-probe claims (`CLAUDE_TO_CODEX_*`, `CODEX_TO_CLAUDE_*` patterns) and claims named by dedup annotations are excluded from the cue index until curation (`suppress_stale` via L14-AUTONOMOUS-CURATION when it exists). (d) While correction claims exist without edges (P1-5 legacy), the index treats an annotation that names duplicates as a suppression hint: duplicates get `negative_memory=false, dedup_hint=true` and WP2 collapses them to the authoritative item.

**WP2.** (a) Explicit relationship to the Librarian: **two channels, one normalizer**. Firing = push addressed by world contact, no query, exact/prefix/signature only. Librarian (fixed recall) = pull addressed by question. UL neither replaces nor waits for the Librarian, except for metrics (B10). (b) Cue index covers ALL durable kinds — this also closes the audit gap "L0 sees only claim_card": fingerprints, skills, capsules, experience cases fire even though L0 never returned them; add test T-B2. (c) `candidates_considered`-style funnel honesty applies: FiringResult reports matched/deduped/suppressed counts truthfully (no theater — audit §3.1-код is the anti-pattern).

**WP3.** (a) Hard precondition: a non-empty edge population. Sources in order: WP4 `co_change` (deterministic, no agent cooperation needed), UL onboarding edges (`concept_implemented_by`, `capsule_covers`, `card_covers`), remediation §4.4 live edges (`belongs_to`, `supersedes`). Activation ships only after the pilot project has ≥ 500 edges; before that, WP2 exact firing runs alone. (b) `supersedes` edges feed `duplicate_penalty` in both channels.

**WP5.** (a) Reality: memory is ~all-candidate (0 promotions in 395 revisions). Capsule inputs therefore accept candidate-grade claims, and every capsule sentence derived from a candidate claim renders with the existing `candidate_only` marking; capsules never upgrade epistemic status (epistemic conservation). (b) Capsule/card bodies feed the denormalized `search_text` field (remediation §1.4 step 1) so the Librarian can also find them — one write, two channels. (c) UTF-8 guard on bodies; Unicode token counting.

**WP7.** Split by host tier (B7). Additional requirements: (a) injection receipts are observability writes with client `write_id`, idempotent, and follow the §4.1 revision decision — never silently advance truth revision; (b) all UL dispatch/response code lives in decomposed modules per B3 (LOC lint: `mcp_stdio.rs` line count must not grow from UL commits — add a CI check); (c) response text stays one-line + structuredContent (implemented convention).

**WP8.** (a) Blocked on P0-2 fix (B3). (b) Arms per B5.5. (c) Exploration-token metering uses the host's observed tool traffic via cognitive observations; where a host exposes no per-tool token counts, use byte counts of tool I/O as the deterministic proxy (documented in the ledger config).

**WP10.** (a) Prediction capture binds to implemented objects: `material_frame.expected_observable` (+ `verifier`, `causal_bridge`) at compile time; probe expectations where probes exist; matching joins registered verifier runs (blake3-pinned commands are already executable ground truth). (b) Influence side uses `eliot_memory_influence_trace` with its `influence_class` enum verbatim; `downstream_outcome_ref` remains the anti-falsification gate — UL adds no bypass. (c) **Promotion-drought bridge:** a hit-scored `prediction_record` whose proof cited claim X and whose verifier run passed constitutes verifier-linked evidence for X in the EXISTING promotion pipeline (UL supplies evidence only; promotion authority unchanged). Side-effect KPI: ≥ 1 claim reaches `supported`/`verified` on the pilot within 2 weeks of UL-6 — ending the zero-promotion drought is an explicit UL success signal.

## B7. Host integration tiers (replaces Part A WP7 hook map where hooks are absent)

```text
Tier H (hosts with lifecycle hooks: Codex CLI plugin, Claude Code hooks):
  Part A WP7 injection map applies as written (PreToolUse/PostToolUse/etc.).

Tier T (tool-only hosts, e.g. Claude Desktop via MCPB — the audited surface):
  No PreToolUse exists. Push degrades to two mechanisms, receipts identical:
  1. Bootstrap/packet injection: charter+map ride the bootstrap composition
     response; capsules/cards/negative memory ride compile_packet_l3 sections
     (requires P0-3 — the packet must carry content).
  2. Response piggyback: any UL-relevant tool response MAY carry an optional
     `ul_fired` block (schema per B5.2) when the session's pending_injection
     is non-empty: <= 3 items, <= 400 tokens, payload only for negative
     memory/invariants, handles otherwise, session-deduped. Trigger source on
     Tier T: cues extracted from the agent's own tool inputs/outputs
     (candidate_submit paths, fetch handles, diagnostic signatures in
     cognitive observations).
  Skills instruct Tier-T agents to treat ul_fired as first-class context.

Degradation honesty: injection_receipt.hook_or_surface records the real
channel; EVAL-CUE reports Tier H and Tier T separately.
```

## B8. Updated implementation order (supersedes Part A §6)

```text
UL-0 (inside L15, verification only): confirm prerequisites closed —
      P0-3 content-bearing packets, P1-1 idempotent observability, P1-3
      schemas-from-types for the touched forms, P1-6 minimal live edges,
      §4.5 UTF-8 guard. UL-0 writes nothing.
UL-1 (L16): WP1 + WP2  — cue binding, index, firing; Tier-T piggyback plumbing.
UL-2 (autonomous, starts immediately per B4): WP4 Git mining.
UL-3 (L17): WP7-minimal — negative memory + module-card firing via available
      tier channels; receipts; LOC lint live.
UL-4 (L18): WP5 + WP6 — capsules + onboarding (pilot = eliot-governor repo).
UL-5 (L19): WP7-full + WP8 — full injection map + token ledger + arms.
UL-6 (L20): WP3 activation (edge threshold met) + WP9 + WP10 + exams.
First-value milestone moves to end of UL-3 unchanged in substance: fired
negative memory and cards reach the agent on the audited Tier-T host.
```

## B9. Additional acceptance tests (T-B series)

```text
T-B1  Regression twin of audit T1: after UL-1, the QUARTZ knowledge is
      delivered WITHOUT any query — touching the file/path bound to the
      QUARTZ claims fires them (push channel), independent of recall state.
T-B2  A failure_fingerprint and a skill_card fire on their bound cues even
      though eliot_recall_l0 never returns those kinds.
T-B3  Cue write with destroyed Cyrillic ('????? QUARTZ') is rejected by the
      UTF-8 guard with the documented error, envelope not canonized.
T-B4  Replay of the same injection_receipt write_id yields the original
      receipt; memory truth revision unchanged (per §4.1 decision).
T-B5  Schema roundtrip: every UL form's published schema validates its own
      serde serialization; a deliberately incomplete input returns ONE -32602
      listing ALL missing fields (no -32603 archaeology).
T-B6  CI lint: UL commits do not increase mcp_stdio.rs line count.
T-B7  Control distinguishability (closes audit P2-4): identical task compiled
      in memory_free_control vs include_case_candidates+UL differs in packet
      bytes, injected sections and receipts; the control run has zero UL
      injections.
T-B8  Tier-T piggyback: after a cognitive observation carrying a known error
      signature, the next tool response contains the matched episode in
      ul_fired, once, with a receipt.
T-B9  Nonce-probe claims (rev 389–393 pattern) never appear in cue index,
      firing results, or capsule inputs.
T-B10 Duplicate collapse: the three QUARTZ copies fire as ONE authoritative
      item + dedup note while legacy edges are absent (B6/WP1-d), and as a
      supersedes-suppressed set once §4.4 edges exist.
```

## B10. Metrics quarantine

Influence/`no_useful_memory` statistics recorded before the Librarian (P0-1) and need-logic (P0-2) fixes are **structurally poisoned** (false negatives at scale) and MUST NOT seed UL utility counters, admission tuning, calibration baselines or EVAL-CUE targets. UL analytics start at a recorded `memory_revision` watermark set after those fixes land; earlier data is retained but tagged `pre_librarian_untrusted`.

## B11. No-go additions (extend Part A §8.2)

```text
any UL form published with a hand-written schema or leaking -32603 field errors;
UL code added to mcp_stdio.rs / commands.rs / host_runtime.rs monoliths;
injection receipts or prediction records that are non-idempotent or advance
  truth revision contrary to the §4.1 decision;
UL analytics seeded with pre-Librarian influence statistics;
control mode (memory_free_control) receiving any UL injection;
cue or capsule content accepted with U+FFFD / mojibake patterns;
activation enabled below the 500-edge threshold;
UL work started before the B8 UL-0 checklist is green;
any weakening of the B5.4 guard list.
```

---

# Part C — Autonomy law and Codex execution protocol (v1.2, normative; same precedence as Part B)

## C1. Autonomy law (supersedes every approval requirement in Parts A/B)

```text
P17 AUTONOMY DEFAULT. Any step Governor can execute deterministically runs
    automatically on its schedule/trigger with a receipt. There are NO
    blocking human or "controller" approvals anywhere in UL. Deterministic
    validation gates (anchors resolve, budgets hold, skeleton complete,
    idempotency keys) are the only promotion authority for UL artifacts.
    Humans intervene only by exception: supersede an artifact through the
    normal write path (promotion=human_superseded). Supersession is an
    override after the fact, never a gate before it.
    Unchanged canon: this law applies to UL pyramid/mining/injection/exam
    artifacts only. Claim promotion to verified stays verifier-gated;
    action authority, leases and the B5.4 guard list are untouched.

P18 MODEL-TOKEN THRIFT. A ReasoningJob is a last resort, not a default.
    Before writing any model-calling code, consult C2. Every job: input
    <= 4 KiB (handles + excerpts, never whole files), output schema-bound
    with a hard token cap, batched across items where possible, retried at
    most once, then recorded as degraded and the pipeline continues with
    the deterministic fallback. Governor never idles waiting for a model.
```

## C2. Deterministic substitution table (build this BEFORE any model path)

| Output | Deterministic source (no model) | Model writes only |
|---|---|---|
| module_card v0 | template: top symbols, caller count, hotspot score, verifier handle, parent capsule | nothing (v0 ships model-free; sleep may later upgrade wording IF exam/usage flags it) |
| capsule sections ENTRYPOINTS / INVARIANTS / DRAGONS / KEY DECISIONS / VERIFIERS | code graph, invariant_cards, fingerprints+hotspots, decision_notes, verifier map | PURPOSE + BOUNDARIES, <= 120 tokens |
| concept seeds | dirs × mining clusters × manifests, overlap merge | names + purpose lines, ONE batched job |
| system map flow edges | co_change + static call edges between concepts | connective prose <= 600 tokens total |
| charter vocabulary | concept names + manifest metadata | WHAT/FOR WHOM/NON-GOALS <= 200 tokens |
| exam questions + grading | graphs, verifier map, capsule anchors | answering only (that is the exam) |
| firing, activation, mining, ledger, coverage, calibration | pure Rust | never |

## C3. Codex execution protocol (anti-loop, anti-graphomania)

```text
ORDER      Execute B8 strictly: UL-0 checklist, then UL-1..UL-6. Inside a
           stage: schema/types -> store -> engine -> app dispatch -> tests.
           One work item at a time; an item is DONE only when its listed
           acceptance tests pass locally. Do not start two items in parallel.

SCOPE      Touch only files the WP names plus the decomposed modules of B3.
           No renames, no drive-by refactors, no "while I'm here" cleanups,
           no new dependencies, no architecture alternatives. If genuinely
           blocked by the spec, write a 5-line ADR proposal file and CONTINUE
           with the next independent item — never redesign silently.

LOOP GUARD Max 3 attempts on any one failing test/build error. Attempt =
           hypothesis + one change + rerun. After 3: record the blocker in
           the progress ledger (file, error, tried), revert to last green,
           move to the next independent item. Never repeat an identical
           change; never chase clippy/fmt in circles (run `just` gates once
           per item, fix, done).

OUTPUT     Code, tests, schemas. Comments <= 2 lines and only where the
           reason is non-obvious. No essays, no restating this document in
           doc-comments, no README novels, no TODO/FIXME (project rule is
           zero). Commit per completed item, message: "UL-<stage> WP<n>:
           <item> (tests: T<x>,T<y>)". Progress ledger UL_PROGRESS.md gets
           exactly one line per item: id, status(done|blocked), test ids.

TESTS      Write the acceptance test FIRST for each item, in the existing
           phase-suite style (focused suites; deterministic double-run +
           restart pattern from phase_l13). Never mark done on "it should
           work". Never consume a reserved full-suite start.

CONTRACTS  Never discover a form by trial calls (the archaeology disease).
           The type in eliot-types IS the contract: derive the schema from
           it (B5.2), test the roundtrip, done.

STOP       A stage is finished when: its tests are green, receipts exist,
           ledger updated, mcp_stdio.rs LOC unchanged (T-B6). Then STOP and
           start the next stage. When UL-6 finishes: STOP entirely — do not
           invent UL-7.
```

---

# Part D — Item-level implementation plan (v1.3, normative; removes residual decisions)

Part D decomposes UL-0..UL-6 into numbered work items. For each item: files, exact types/signatures, algorithm constants, tests with expected results. Codex executes items strictly in order (C3). Every choice Part A left to "implementation" is fixed here — do not re-open it.

## D0. Conventions and global fixed decisions

```text
D0.1 CAPABILITY BINDING. When an item names an integration point, locate it by
     ripgrep in this order and use the FIRST hit; if none, use the stated
     fallback and write one ledger line "bound: <item> -> fallback". Never
     spend more than 2 search patterns per binding.

D0.2 MODULE LAYOUT (fixed):
     crates/eliot-types/src/ul/{mod,normalize,cue,concept,behavior,injection,
       prediction,config}.rs           — pure types, serde+schemars derives
     crates/eliot-store/src/ul_store.rs and src/surql/ul_schema.surql
     crates/eliot-engine/src/ul/{mod,cue_index,firing,activation,mining,
       capsule,onboarding,injection,ledger,metacog,calibration,exam}.rs
     crates/eliot-app/src/mcp_dispatch_ul.rs, mcp_schemas_ul.rs, commands_ul.rs
     Registration lines in existing monoliths: <= 3 lines each (mod + wire),
     loc-guard tolerance is set to +10 lines for exactly this purpose.

D0.3 TABLE CLASSES (fixed):
     truth-class (canonical write envelope, WriterActor lane):
       concept_node, project_charter, system_map, subsystem_capsule,
       module_card, capsule_build, co_change, hotspot_score, mining_run
     observability-class (idempotent client write_id, does not advance truth
       revision per remediation §4.1):
       injection_receipt, activation_trace, prediction_record, exam_record
     derived-class (Governor-owned, rebuildable, direct store writes, no
       envelopes, receipts only):
       cue_index, dep_reverse_index, pending_injection, coverage_map,
       calibration_score, ul_ab_counter, loc baseline

D0.4 DETERMINISTIC IDS:
     const UL_NS: Uuid = uuid5(NAMESPACE_OID, "eliot-ul")   // compute once, hardcode hex in code comment
     write_id(observability) = uuid5(UL_NS, session_id|task_id|item_ref|surface)
     firing_id  = uuid5(UL_NS, session_id|seq_no)            // seq_no = per-session counter
     build_id   = uuid5(UL_NS, target_kind|target_id|inputs_manifest_blake3)
     mining_run = uuid5(UL_NS, project_id|head_commit|window_config_blake3)
     Replaying the same logical event MUST produce the same id.

D0.5 TOKEN UNIT (supersedes "tiktoken-compatible" in Part A WP5):
     ul_token_estimate(s: &str) -> u32 = (s.len() as u32 + 3) / 4   // UTF-8 bytes
     ALL UL budgets (200/600/500/200, 1200, 700, 400, 120, 30) are enforced
     against this estimator. No tokenizer dependency is added.

D0.6 CONCURRENCY: hot shards = std::sync::RwLock<Arc<ProjectShard>>; update =
     build new shard, write-lock, replace Arc. No new concurrency crates.

D0.7 FIXTURES:
     fixtures/ul_min/        — synthetic repo built BY the test (git init +
       scripted commits, see D3.7); never committed as a git-in-git dir.
     pilot                   — the eliot-governor repo itself.
     All engine/store tests run against a disposable real SurrealDB service
       (same pattern as remediation §1.3: spawn pinned surreal.exe, memory
       mode, random port 84xx, ns/db "ultest", kill by PID in teardown).

D0.8 TEST STYLE: file names crates/<crate>/tests/ul_<stage>_<topic>.rs;
     fn names t<id>_<slug> (e.g. t2_1_exact_firing). Every test asserts
     concrete values listed in its item; determinism tests run the operation
     twice + after store restart and assert byte-identical serialized output.

D0.9 NO NEW DEPENDENCIES anywhere in UL. If an item seems to need one, the
     fallback in its spec is the law.
```

## D1. UL-0 — prerequisite verification (read-only, one test file)

File: crates/eliot-app/tests/ul_0_prereq.rs. Each check is a test; a red test = blocker line in ledger; UL-1 may not start while any is red (WP4/UL-2 exempt).

```text
UL-0.1 t0_1_packet_carries_content: compile a packet with 1 known candidate
       handle in mode include_case_candidates; assert historical_memory
       contains the claim statement text (P0-3 done).
UL-0.2 t0_2_observability_idempotent: write the same influence trace twice
       with one write_id; assert single record + unchanged truth revision.
UL-0.3 t0_3_schema_roundtrip_frame: fetch published schema for compile input;
       validate a serde-serialized MaterialPacketFrame against it (P1-3).
UL-0.4 t0_4_live_edges_exist: submit a candidate with belongs_to topic;
       fetch_l2 returns >= 1 relation (P1-6 minimal).
UL-0.5 t0_5_utf8_guard: submit statement "????? QUARTZ провер"; assert
       typed rejection error mentioning encoding (remediation §4.5).
```

## D2. UL-1 — cue binding, index, firing (WP1+WP2)

### UL-1.1 Normalizers — crates/eliot-types/src/ul/normalize.rs

```rust
pub fn normalize_path(raw:&str, project_root:&str) -> String
// backslashes->'/'; strip project_root prefix; collapse "//"; trim "./";
// lowercase ONLY on windows paths (cfg!(windows) at CALLER's data origin is
// unknowable -> rule: lowercase ALWAYS; paths are compared case-insensitively
// project-wide). Result never starts with '/'.
pub fn normalize_symbol(raw:&str) -> String   // trim, collapse "::"+ dedupe, lowercase
pub fn tokenize_query(raw:&str) -> Vec<String>
// unicode lowercase(char::to_lowercase), split on !is_alphanumeric, drop
// stop-words (list below), dedupe preserving order, cap 12.
pub fn command_pattern(argv:&[String]) -> String  // argv[0] basename + first
// token not starting with '-' ; join with ' '
pub fn error_signature(tool_id:&str, rule_id:&str, message:&str, path:&str) -> String
// msg_class = first 80 chars of message with digits->'#', hex>=8 chars->'@',
//   quoted substrings removed; path_class = normalize_path then strip file
//   name digits; return hex of blake3(tool_id|rule_id|msg_class|path_class)
//   full 64 chars, prefix "sig:".
pub const STOP_EN:[&str;40]=["a","an","the","and","or","of","to","in","on","for",
 "is","are","was","were","be","been","it","this","that","these","those","with",
 "as","by","at","from","we","you","i","do","does","did","can","could","should",
 "would","when","what","how","why"];
pub const STOP_RU:[&str;40]=["и","в","во","не","на","я","с","со","как","а","то",
 "все","она","так","его","но","да","ты","к","у","же","вы","за","бы","по","ее",
 "мне","было","вот","от","о","из","ему","когда","что","это","для","или","если","при"];
```

Tests crates/eliot-types/tests/ul_1_normalize.rs:

```text
t1_3_normalizer_identity: property (proptest is in tree? if not: 200 fixed
  fuzz strings from a seeded LCG) — tokenize_query(x)==tokenize_query(x)
  across two calls and equals the store-side re-export (single symbol —
  assert fn pointer identity is impossible; assert both paths import
  eliot_types::ul::normalize, enforced by a grep test: no second definition
  of "fn tokenize_query" in workspace).
tD2_paths: normalize_path("Crates\\Eliot-Store\\src\\LIB.rs", root) ==
  "crates/eliot-store/src/lib.rs".
tD2_sig_stability: same diagnostic with different line numbers/hex addrs
  yields identical signature; different rule_id yields different.
tD2_tokens: tokenize_query("Когда допустимо читать из канонического
  инстанса без fallback") == ["допустимо","читать","канонического",
  "инстанса","fallback"] (stop-words removed, order kept).
```

### UL-1.2 Cue types — crates/eliot-types/src/ul/cue.rs

CueKind/MatchMode/Strength enums, CueBinding struct exactly as Part A §2.1; JsonSchema derive; roundtrip test t_b5_cue_schema (serialize→validate against schemars output).

### UL-1.3 Store schema — surql/ul_schema.surql (apply immediately after 000_schema)

```sql
DEFINE TABLE cue_index SCHEMALESS;            -- derived
DEFINE INDEX idx_cue ON cue_index FIELDS project_id, cue_kind, cue_value;
DEFINE TABLE pending_injection SCHEMALESS;    -- derived
DEFINE INDEX idx_pend ON pending_injection FIELDS session_id;
DEFINE TABLE injection_receipt SCHEMALESS;    -- observability
DEFINE INDEX idx_inj_write UNIQUE ON injection_receipt FIELDS write_id;
DEFINE INDEX idx_inj_sess ON injection_receipt FIELDS session_id, item_ref;
-- co_change, hotspot_score, mining_run, concept tables, prediction_record,
-- dep_reverse_index, coverage_map, calibration_score, ul_ab_counter: one
-- DEFINE TABLE + the indexes of Part A §2.11, same style, all in this file.
```

ul_store.rs functions (all via existing RPC exec path, bind by grepping "recall_l0" usage): upsert_cue_rows, delete_cue_rows_for, load_cue_shard(project)->Vec<CueRow>, put_pending, take_pending(session)->Vec<Item>, write_observability(write_id, table, json) with ON CONFLICT return-existing semantics (SELECT by write_id first, insert if absent — two statements in one transaction).

### UL-1.4 Write-side validation — engine, bind to the candidate-admission fn (grep "fn admit" / "candidate_submit" in eliot-engine; fallback: the fn called by app dispatch for eliot_agent_candidate_submit)

```text
validate_cue_bindings(env) -> Result<(),UlError::CueBindingRequired{detail}>
rules exactly Part A §2.1 + B6/WP1; durable kinds list (fixed):
  ["claim","decision","failure_fingerprint","skill","invariant",
   "experience_case","capsule","module_card"]
UTF-8 guard (UL-1.5) runs BEFORE binding checks.
Error surfaces as MCP -32602 with code CUE_BINDING_REQUIRED and the full
list of failed rules (never one-at-a-time).
```

### UL-1.5 UTF-8 guard — eliot-types fn `mojibake(s)->Option<&'static str>`

```text
reject if: contains '\u{FFFD}'  -> "replacement_char"
        or regex-free scan: >=3 consecutive '?' where the 8 chars before or
           after contain a char in ranges 0x400-0x4FF (Cyrillic) -> "qmark_run"
Applied to: claim statements (bind into admission), cue_value, capsule/card
body_md, decision rationale fields. Test t_b3 uses the literal audit string.
```

### UL-1.6 Backfill CLI — commands_ul.rs: `ul backfill-cues --project <id> [--apply]`

```text
default dry-run prints TSV: record_id, kind, disposition
dispositions: bound_from_evidence | bound_from_diagnostic | excluded_nonce
  | excluded_dedup_hint | degraded_cue
nonce regex (fixed): "(CLAUDE_TO_CODEX|CODEX_TO_CLAUDE)_[A-Z0-9]+"
--apply writes bindings via normal envelopes (supersession of the record's
  metadata, not payload), zero ReasoningJobs (assert in test by broker
  counter == 0). Test tD2_backfill on 6 synthetic records covering each
  disposition; expected TSV committed as golden file.
```

### UL-1.7 CueIndexService — engine/ul/cue_index.rs

```rust
pub struct CueKey{kind:CueKind, value:String}
pub struct CueEntry{record_ref:String, record_kind:String, strength:Strength,
  negative:bool, dedup_hint:bool, token_estimate:u32}
pub struct ProjectShard{exact:HashMap<CueKey,Vec<CueEntry>>,
  dir_prefix:Vec<(String,Vec<CueEntry>)>}  // sorted by prefix, binary search
pub struct CueIndexService{shards:RwLock<HashMap<ProjectId,Arc<ProjectShard>>>}
impl: rebuild(project) (from store, sort entries: negative desc, then
  record_kind rank [fingerprint0,invariant1,decision2,claim3,episode3,skill4,
  capsule5,card5], then record_ref asc — total order => determinism);
  apply_outbox(event) (incremental); fire(project,&[Cue])->FiringResult
  exactly Part A WP2 algorithm, cap 8 + overflow handle.
```

Tests ul_1_cue_index.rs: t2_1 (3 bound records, order asserted by ids), t2_2 (supersede then fire -> absent after apply_outbox), t2_3 (rebuild after restart — byte-identical FiringResult JSON), t2_4 (1000 adversarial values incl. 10KiB string, emoji, mixed scripts: no panic, foreign project_id never present), t_b2 (fingerprint + skill fire), t_b10 (three QUARTZ-like claims, one authoritative: result contains 1 payload item + dedup note listing 2 collapsed ids).

### UL-1.8 Tier-T piggyback plumbing — engine/ul/injection.rs + app attach

```text
on cognitive-observation ingest and on candidate_submit: extract cues
(normalize paths/symbols from payload fields listed: file paths in evidence
anchors, "path", "file", diagnostic signature fields), call fire(), put
pending_injection rows (session, item_ref, render_form, fired_cues, expiry =
now+30min).
attach point: single fn ul_attach(session,&mut response_json) called from
mcp_dispatch_ul-exported hook invoked by each dispatch wrapper (one wiring
line per tool in the decomposed dispatch); it drains pending up to 3 items /
400 ul-tokens, renders block:
  "ul_fired":[{"ref":..,"kind":..,"line":<=160 chars,"uri":"eliot://..",
               "payload":<only negative|invariant, <=400 tokens>}]
writes injection_receipt rows (write_id per D0.4) BEFORE returning.
```

Test t_b8: observation with known signature -> next current_state response contains ul_fired with the episode, second call contains nothing (dedup), receipt table has exactly 1 row, truth revision unchanged (t_b4 shares fixture).

**UL-1 exit:** tests t1_1..t_b10 above green; ledger lines written; schemas published for changed candidate_submit input (t_b5).

## D3. UL-2 — Git mining (WP4), autonomous

### UL-3.1..7 condensed items

```text
UL-2.1 exec: bind existing git adapter (grep "GitState" in engine); fallback:
  run via the SAME process-exec path verifiers use (grep "Command::new" in
  verifier runner) with fixed argv:
  git -C <root> log --no-merges --date=unix
      --pretty=format:C|%H|%an|%ad|%s --name-only -n <max_commits>
  parse: lines starting "C|" open a basket; following non-empty lines are
  paths until next "C|"; normalize_path each; drop paths matching profile
  globs (default: target/**, node_modules/**, **/*.lock, dist/**, vendor/**).
UL-2.2 basket merge: same author AND |t1-t2|<=1800s AND both<=20 files.
UL-2.3 pairs: for basket size 2..=30 (bigger baskets skipped as bulk moves),
  unordered pairs; accumulate support, per-direction counts. Persist rule:
  support>=3 AND max(conf)>=0.5. Write in envelope batches of 50 edges,
  idempotency key = mining_run_id + ":" + chunk_no; payload kind
  "tool_observation", taint "derived". static_edge_exists: query code graph
  adapter if bound, else false with note "static_unknown".
UL-2.4 hotspots: churn_decayed = sum over commits exp(-age_days*ln2/90);
  base = percentile rank among files with churn>0, score =
  round(base*100*(0.5+0.5*bugfix_density)); if failure_density>0:
  score=min(100, score*1.2). Round half-up. Store all inputs on the row.
UL-2.5 fix classifier v "ul-fixclass-1": lowercase msg contains any of
  [fix,bug,hotfix,patch,revert,regression,repair,исправ,фикс,чин,баг,откат].
UL-2.6 scheduling: register nightly 02:30 local via existing scheduler (grep
  "JobScheduler" / "schedule"); fallback: run at daemon start if last
  mining_run older than 20h. CLI: `ul mine-git --project X [--full]`.
UL-2.7 tests ul_2_mining.rs: fixture builder makes a temp git repo:
  25 commits; files a.rs+b.rs co-committed 8 times (never imports), c.rs
  touched 12 times with 6 "fix:" messages, noise files. Asserts:
  t4_1 edge(a,b): support==8, conf>=0.99, static_edge_exists in {false,
       "static_unknown"}; t4_2 rerun same HEAD -> receipt "noop", row count
  unchanged; t4_3 hotspot(c.rs) score in [70..=100] and > score(a.rs);
  t4_4 "target/gen.rs" absent from all tables.
```

**UL-2 exit:** t4_1..t4_4 green; nightly registration visible in receipts; runs with zero ReasoningJobs (broker counter).

## D4. UL-3 — minimal injection + guards (WP7-minimal)

```text
UL-3.1 injection_receipt writes (D0.3/D0.4) — already exercised by t_b8/t_b4.
UL-3.2 planner order fn (fixed total order): negative desc, kind rank
  (invariant, decision, card, claim, episode, skill, capsule), fired-exact
  before activation, token_estimate asc, ref asc.
UL-3.3 loc-guard: file ci/ul_loc_baseline.json {"mcp_stdio.rs":N,
  "commands.rs":N,"host_runtime.rs":N} written once at UL-3 start (actual wc
  -l). just target `ul-loc-guard`: recompute, fail if any grows by >10.
  Wire into existing `just` gate chain (one line). Test t_b6 runs the target.
UL-3.4 first-value demo test t_fv (ul_3_first_value.rs): end-to-end on
  disposable DB: submit fingerprint bound to "src/net/session.rs" ->
  observation touching that path -> next response carries payload fingerprint
  -> receipt present. This test is the UL-3 gate.
```

## D5. UL-4 — concept layer + onboarding (WP5+WP6)

### UL-4.1 Deterministic section fillers — engine/ul/capsule.rs (templates fixed)

```text
ENTRYPOINTS:  "- {symbol} ({path}:{line}) [{anchor_ref}]"   max 3, source:
              code graph exported/public symbols ranked by inbound calls;
              fallback (no graph): files matching {lib.rs,main.rs,mod.rs}.
INVARIANTS:   "- {invariant_id}: {title}"                    all active in scope
DRAGONS:      "- FF {id}: {one_line} (hits {n})" then "- hotspot {path}
              score {s}" — max 3 each, ranked by failure_density, score.
KEY DECISIONS:"- {id}: {chosen_because|first 80 chars}"      max 3, newest.
VERIFIERS:    "- {verifier_id}: {command|first 60 chars}"    all mapped.
Every line ends with its anchor handle; lines are sorted by the stated rank
then id — byte-determinism required (test doubles the build).
```

### UL-4.2 ReasoningJob prompts (exact text; output schema-bound; input <=4KiB)

```text
JOB CapsuleDraftCandidate — user content:
  "SUBSYSTEM: {name}\nFILES(sample): {<=15 paths}\nDETERMINISTIC SECTIONS
   (already final, do not restate): {sections text}\nWrite JSON
   {\"purpose\":str,\"boundaries\":str}. Combined ul-token budget 120.
   Operative statements only. Cite anchors inline as [a:{id}] using ONLY ids
   from ANCHORS: {id list}. No praise, no hedging, no meta."
JOB ConceptExtractionCandidate (ONE batch) — user content:
  "SEEDS:\n{seed_i: dirs, top paths, cluster stats}\nReturn JSON
   [{\"seed\":i,\"name\":snake_case<=24 chars,\"purpose\":<=30 ul-tokens}].
   Names unique."
JOB SystemMapDraftCandidate: accepted concepts + top flow edges -> body_md
   <=600 ul-tokens, cite [a:id].
JOB CharterDraftCandidate: map + manifest/README excerpts(<=2KiB) ->
   sections WHAT/FOR WHOM/TOP INVARIANTS/NON-GOALS/VOCABULARY, <=200.
Validation failures (budget, unknown anchor, bad JSON): retry ONCE with the
   error appended; then deterministic fallback: purpose="(pending)",
   boundaries=dir list — capsule still ships (promotion=auto, note
   "degraded_prose"), pipeline continues (P18).
```

### UL-4.3 Build/dirty/onboarding mechanics

```text
capsule_build validation fn order: skeleton -> anchors resolve -> budget ->
  write build + target via envelope (one transaction group per target).
dep_reverse_index rows written same transaction; outbox subscriber
  (engine/ul/capsule.rs::on_outbox) marks dirty (reason = event kind + ref).
sleep/maintenance: bind existing scheduler; job recompiles <=5 dirty targets
  oldest-first; receipts per target.
onboarding stages exactly B6/Part A WP6 with D5 jobs; checkpoint record
  after each stage: derived row onboarding_ckpt{project, stage, blake3(inputs)};
  resume skips stages whose ckpt matches.
```

### UL-4.4 Tests ul_4_capsule.rs / ul_4_onboarding.rs

```text
t5_1 unknown anchor [a:zzz] -> build rejected, anchor id in build record.
t5_2 edit dep file -> dirty within one subscriber tick; injected render
     starts with "[STALE since".
t5_3 body of 501 ul-tokens -> budget_check fail recorded, not promoted.
t5_4 valid charter -> promotion=="auto", receipt chain complete.
t5_5 recompile -> supersedes prior build_id; skeleton intact (regex on
     section headers).
t6_1 onboard fixtures/ul_min (12 files, 3 planted dirs) -> exactly 3
     concepts (deterministic floor rule), 3 capsules, map+charter promoted,
     coverage_map has zero blind; ReasoningBroker counter == 3+3 == 6? NO:
     N_subsystems + 3 = 6 jobs MAX; assert count <= 6 (fallbacks may reduce).
t6_2 kill after STAGE 3 (test hook), resume -> no duplicate ckpt, final
     state identical to uninterrupted run (byte-compare coverage_map JSON).
t6_3 every fixture file maps to exactly one concept; superseding a
     concept name leaves cue bindings firing (bindings reference paths,
     not names).
t6_4 job receipts: each input payload <= 4096 bytes.
```

**UL-4 exit:** t5_1..t6_4 green + onboarding of pilot repo completes hands-off (manual run, receipts archived).

## D6. UL-5 — full injection + token ledger (WP7-full + WP8)

```text
UL-5.1 session composition: bind bootstrap composition (host_runtime greeting
  or first current_state per session — grep "session_status"): attach
  charter payload + map payload + coverage one-liner, budget 1200; framing
  attach on first compile of a task: capsules intersecting scope (max 3),
  danger lines, novelty line.
UL-5.2 ledger: derived table ul_ledger{task_id,task_class,injected_tokens,
  exploration_bytes,arm}; exploration = sum of byte sizes of read-class tool
  IO observed via cognitive observations; read-class name list (fixed):
  [fetch_l2, recall_l0, current_state(after first), any observation whose
  payload marks tool_kind in {read,grep,list,lsp}].
  net = injected_tokens - exploration_bytes/4 (same unit as D0.5).
UL-5.3 arms: ul.token_ledger.ab_mode="parity" for first 2 weeks per project
  (persisted ul_ab_counter per task_class; even ordinal=treatment). Control
  arm: planner suppresses ALL UL attaches for the task AND compile runs
  memory_free_control (t_b7 asserts both).
UL-5.4 downgrade automaton (derived state per task_class):
  states payload_ok -> handles_only; transition when n>=10 tasks in arm=on
  AND median(net)>0; on transition write report_manifest
  "UL-DOWNGRADE-{class}-{yyyymmdd}" with the 10 task ids and medians;
  re-enable only via config edit (no auto-return).
UL-5.5 tests ul_5_ledger.rs: t8_1 harness: scripted task replayed twice
  (arm on/off) against fixture memory; assert exploration(on) <
  exploration(off) given planted card, and ledger rows match hand-computed
  bytes; t8_2 classification golden; t8_3 forced positive-net fixture (10
  synthetic tasks) -> state flips, report exists, planner emits handles only.
```

## D7. UL-6 — activation, metacognition, calibration, exams

```text
UL-6.1 activation (WP3): graph load from edge tables into ArenaGraph
  {nodes:Vec, adj:Vec<(u32,f32,EdgeKind)>}; weights exactly Part A WP3;
  spread exactly Part A (max-accumulate, depth 2, fanout 20, thr 0.35);
  enable flag auto: edge_count(project)>=500. Bench: build synthetic graph
  with LCG seed 42 (50k nodes, 200k edges), assert compute p95 <= 30ms over
  100 runs (release profile; test marked #[ignore] wired into a just bench
  target, not CI).
  CONSTANT FIX (normative, supersedes Part A WP3 step 2): global decay 0.5
  applies only from depth 2; seed-adjacent hops use activation(child) =
  parent * edge_weight. (Otherwise a strong co_change hop 1.0*0.7*0.8*0.5
  = 0.28 would fall below the 0.35 threshold — wrong.)
  t3_1: co_change(a,b,conf 0.8), no static edge -> activation(b) ==
        1.0*0.7*0.8 = 0.56 (kept, asserted to 1e-6); a depth-2 neighbor via
        card_covers gets 0.56*0.9*0.5 = 0.252 (suppressed, in trace).
  t3_2 hub node 10k edges -> exactly 20 children expanded (trace proves).
  t3_3 double-run byte-identical trace.
UL-6.2 coverage/novelty/danger (WP9): thresholds as Part A; recompute
  incrementally from outbox; t9_3 golden compare vs full recompute.
UL-6.3 gate integration: on compile validation (material_frame path), when
  fresh capsule exists for a touched subsystem: require each capsule
  invariant id present in frame.negative_memory_checked/invariants OR in new
  optional frame field waived_invariants[{id,reason}]; missing -> compile
  response field ul_gate:{status:"require_packet_refresh",missing:[ids]}
  (advisory on Tier T — do not block, DO record). Blind subsystem + R2-class
  edit_kind -> ul_gate require_probe with 1 suggested cheapest verifier.
  t9_1/t9_2 assert exact ul_gate payloads.
UL-6.4 prediction matcher: subscriber on verification-run and observation
  events; join window = same task_id, else 24h sweeper marks unresolvable.
  blast actual paths: git diff --name-only {base}..{head} via UL-2.1 exec
  when task branch known, else changed-path set from observations.
  hit rules exactly Part A WP10. calibration: hit=1, partial=0.5, miss=0;
  hit_rate=sum/ n_resolved; confidence map low=.6 med=.8 high=.95, Brier
  over resolved only; trend degrading = 3 consecutive weekly deltas < 0.
UL-6.5 exam job weekly Sun 03:00: generation per Part A WP10 with fixed
  forms: Q-blast truth = union(static neighbors depth1, co_change conf>=.6,
  verifier map); grade = F1 of normalized sets, pass>=0.6; subsystem score
  = mean of 3; score<0.5 -> capsule dirty(exam_failure). Exam answering job
  input: charter+map ONLY + question (cold condition), output JSON list of
  paths/ids. exam_record observability rows; report_manifest
  "UL-EXAM-{yyyy-Www}".
UL-6.6 tests ul_6_predict.rs / ul_6_exam.rs: t10_1 planted pass-verifier ->
  hit attributed to subsystem "net" (fixture concepts); t10_2 blast fixture:
  predicted {a,b,c}, actual changed {a,b}, failed verifiers {v1} predicted
  {v1,v2} -> precision paths 2/3, recall 1.0, verifier precision 0.5 —
  assert exact fractions; t10_3 plant stale capsule (wrong entrypoint) ->
  exam Q-entry F1<0.5 -> dirty(exam_failure) present; t10_4 audit write
  kinds of all exam artifacts: none in truth-class tables.
```

**UL-6 exit = UL DONE:** Part A §8.1 items 1–10 re-run as a checklist test file ul_done.rs (each item one test or a receipt assertion); Part B/C gates green (T-B*, t_fv); ledger final line "UL v1 complete".

## D8. Test matrix (single source of truth for CI wiring)

| IDs | File |
|---|---|
| t0_1..t0_5 | eliot-app/tests/ul_0_prereq.rs |
| t1_1,t1_2,t1_4,t_b3,t_b5,tD2_* | eliot-types/tests/ul_1_normalize.rs, eliot-store/tests/ul_1_write.rs |
| t2_1..t2_4,t_b2,t_b10 | eliot-engine/tests/ul_1_cue_index.rs |
| t_b8,t_b4 | eliot-app/tests/ul_1_piggyback.rs |
| t4_1..t4_4 | eliot-engine/tests/ul_2_mining.rs |
| t_b6,t_fv | eliot-app/tests/ul_3_first_value.rs |
| t5_1..t5_5 | eliot-engine/tests/ul_4_capsule.rs |
| t6_1..t6_4 | eliot-engine/tests/ul_4_onboarding.rs |
| t7_1..t7_5,t_b7 | eliot-app/tests/ul_5_injection.rs |
| t8_1..t8_3 | eliot-engine/tests/ul_5_ledger.rs |
| t3_1..t3_3,t9_1..t9_3 | eliot-engine/tests/ul_6_activation.rs, ul_6_metacog.rs |
| t10_1..t10_4 | eliot-engine/tests/ul_6_predict.rs, ul_6_exam.rs |
| done checklist | eliot-app/tests/ul_done.rs |

Part A T-numbers map 1:1 to these snake ids (T2.1=t2_1 etc.). CI: add one focused-suite line per stage to the existing just test targets; never the full workspace suite.

## D9. Config registry final (defaults; every key snapshot-referenced)

Part A §5 TOML stands, plus:

```toml
[ul]
token_unit = "bytes_div_4_v1"
[ul.mining]
fix_classifier = "ul-fixclass-1"
basket_author_window_s = 1800
basket_max_files = 20
pair_basket_max = 30
[ul.injection]
piggyback_max_items = 3
piggyback_budget_tokens = 400
pending_expiry_min = 30
[ul.activation]
seed_adjacent_no_decay = true
enable_min_edges = 500
[ul.exam]
cron = "Sun 03:00"
pass_f1 = 0.6
[ul.loc_guard]
tolerance_lines = 10
```

## D10. Closed-decision register (do not re-open)

```text
token counting = bytes/4 (D0.5)          concurrency = std RwLock (D0.6)
ids = uuid5 over UL_NS (D0.4)            derived tables bypass envelopes (D0.3)
git access = adapter else verifier-exec  stop-words = the two 40-word lists
fix regexes = ul-fixclass-1              seed-adjacent activation skips decay
piggyback = 3 items / 400 tokens         exam pass = F1 0.6
prompts = D5 verbatim                    fallback prose = "(pending)" + note
schemas = schemars from types, always    retries: model 1, build/test 3 (C3)
```

---

# Part E — Agent surface: plugin + skills for Codex and Claude (v1.4, normative)

The audit measured the cost of a hostile surface: 5 calls to discover the material_frame form, 10 for the influence trace, three calls to bootstrap a session, a doubled 2x12 tool registry, and skills that prescribe rituals the agent must hand-assemble. Part E redesigns the agent-facing layer so that using ELIOT is always the cheapest available move. Rule of thumb enforced throughout: **the agent spends tokens on the task; the server spends cycles on the ceremony.**

## E0. Surface budgets (hard, tested)

```text
sum of all tool descriptions visible to a worker profile   <= 900 ul-tokens
one tool description                                       <= 90
AGENTS.md ELIOT section (Codex, always in context)         <= 250
skill body (loaded on trigger)                             <= 500; description <= 25
ul_boot block (once per session)                           <= 1200
ul_fired block (per response)                              <= 400, max 1 ul block per response
error payload                                              <= 350, MUST include minimal_valid_example
Responses never echo request payloads back. Field names are identical across
all tools: task_id, session_id, handle, write_id, dry_run, project_id.
```

## E1. One registry, role-scoped visibility

```text
E1.1 Single registration (remediation §4.6): the MCPB plugin is the only
     server entry on hosts where it is installed; ship a doctor check
     `ul doctor --host` that detects the doubled registry and prints the
     exact config line to delete.
E1.2 Per-profile tool visibility (server-side, keyed by access_profile):
     worker profile exposes 7 tools:
       eliot_current_state, eliot_recall_l0, eliot_fetch_l2,
       eliot_compile_packet_l3, eliot_agent_candidate_submit,
       eliot_memory_influence_trace, eliot_write_cognitive_observation
     admin/operator profile exposes all 12 (adds session_status,
     project_identity, lifecycle/registration tools).
     Rationale: session_status + project_identity become unnecessary for
     workers after E4.1 auto-boot; hiding them saves ~150 always-loaded
     tokens and removes two decision points.
E1.3 Unobserved tools keep their names; their descriptions are rewritten to
     the E2 pattern and count against the E0 budget.
```

## E2. Tool descriptions (verbatim; replace existing)

Pattern: `<verb phrase>. Use when <trigger>. Needs: <fields>. Returns: <key outputs>.` No marketing, no theory, no "governed epistemic" vocabulary.

```text
eliot_current_state        "Project memory snapshot + revision. Use at doubt
  about current truth. Needs: nothing. Returns: verified/contested claims,
  revision fence."
eliot_recall_l0            "Search memory by keywords. Use when you need
  knowledge NOT already injected (ul_boot/ul_fired). Needs: query (plain
  words). Returns: handles + one-liners."
eliot_fetch_l2             "Expand memory handles to full cards. Use only for
  handles you will act on. Needs: handles[]. Returns: cards + relations."
eliot_compile_packet_l3    "Task context packet + prefilled frame_stub. Use
  BEFORE any material edit. Needs: goal (task_id auto). Returns: packet,
  frame_stub (edit <=5 fields), verifier, ul_gate."
eliot_agent_candidate_submit "Save a lesson/decision/failure to memory. Use
  after solving anything non-obvious or failing. Needs: statement, kind,
  expected_reuse_note (bindings auto from your session). Returns: handle."
eliot_memory_influence_trace "Acknowledge memory you used. Minimal form:
  memory_handle, influence_class[, downstream_outcome_ref]. Server fills the
  rest. Returns: receipt."
eliot_write_cognitive_observation "Record a tool/test observation (errors,
  diagnostics). Use on notable failures. Needs: payload. Returns: receipt;
  may trigger ul_fired on next call."
```

Test t_e1 computes ul_token_estimate over the worker-profile tool list JSON and asserts <= 900; per-tool <= 90.

## E3. Zero-archaeology contract (server-side; applies to every tool)

```text
E3.1 Aggregated validation: any invalid input returns ONE -32602 with:
     {code, missing[], invalid[], minimal_valid_example} where the example is
     a copy-pasteable JSON that WOULD succeed for this session (real task_id,
     real handles when known). Raw -32603 serde leaks are a release blocker
     (restates B5.2 — here it covers ALL tools, not only UL forms).
E3.2 dry_run:true accepted by candidate_submit, influence_trace, compile
     (validate_only) — full validation, zero mutation, response marked
     dry_run. One call teaches the form; state untouched. Test t_e3.
E3.3 Defaults so minimal calls work (fixes audit §3.3 items 4-5):
     task_id     — optional everywhere; resolved to the session's active
                   task; if none, a session-scoped implicit task is created
                   (kind=unscoped) and returned in the response.
     max_tokens  — default 1200.  memory_mode — default include_case_candidates.
     write_id    — optional on observability writes; server derives
                   uuid5(UL_NS, canonical_payload_blake3) => forgotten
                   write_id still yields idempotent retries.
E3.4 material_frame published schema regenerated from the serde type with all
     16 fields and the {from,to,relation} hop shape (kills the 5-call
     discovery); frame_stub (E4.3) makes hand-assembly unnecessary anyway.
E3.5 Consistency lint (test t_e5): every tool input/output field name that
     denotes the same thing uses the same identifier across all schemas.
```

## E4. Convenience surfaces (server does the ceremony)

### E4.1 Auto-boot (kills the 3-call session opening)

```text
Server tracks first successful tool response per (session, project): attach
ul_boot block: {identity_line, revision, charter payload, map payload,
coverage_line, active_task?} within 1200 budget (charter+map omitted with
note "not onboarded" when absent). session_status / project_identity become
admin tools (E1.2). Skills say: "start working; context arrives with your
first call." Receipt: injection_receipt(surface=session_start).
Test t_e4: fresh session, FIRST call is recall; response carries ul_boot;
second call carries none.
```

### E4.2 auto_bind (kills the write-friction that would kill WP1 adoption)

```text
candidate_submit: when cue_bindings omitted and auto_bind != false, server
derives bindings from the session touched-set (normalized paths/symbols/
signatures accumulated from observations, fetches, compiles this session):
  primary  = touched cues whose value occurs in statement/payload text
  secondary= remaining touched cues, most recent first
  cap 5; expected_reuse_note remains agent-supplied (the one thing only the
  writer knows). If nothing derivable: CUE_BINDING_REQUIRED error carries
  suggested_bindings[] ready to copy (E3.1 example includes them).
Receipts record binding_source=auto|explicit per binding. Test t_e6: submit
with only {statement,kind,expected_reuse_note} after touching two files ->
record has >=1 primary auto binding to a touched path; dry_run variant shows
the same bindings without writing.
```

### E4.3 frame_stub (kills the 16-field composition)

```text
compile_packet_l3 response gains frame_stub: a COMPLETE valid
MaterialPacketFrame prefilled by Governor:
  task_id, verifier (from verifier map), causal_bridge seeded from code
  graph for the write-set (intent->owner->symbol hops), negative_memory_
  checked (from firing results), stop_condition template, active_plan
  template ["<step1>"], completed_work=[], killed_paths=[],
  next_allowed_action template, expected_observable "" (MUST be filled).
Agent edits <= 5 fields: intent, expected_observable, next_allowed_action,
active_plan, (optionally) bridge wording — then submits the stub back with
stub_rev; server validates the diff cheaply. Unedited expected_observable
=> validation error naming exactly that field.
Test t_e7: stub from fixture compile is schema-valid as returned except the
one intentionally empty field; filling 2 fields passes validation.
```

### E4.4 Influence ack — minimal form (kills the 14-field trace)

```text
influence_trace accepts EITHER the full audit form OR the minimal ack:
  {memory_handle, influence_class[, downstream_outcome_ref]}
Server derivation table (fixed):
  admission_decision   <- record status (candidate->require_revalidation,
                          verified->include_verified, supported->include_supported)
  epistemic_status_at_use <- record status
  packet_id            <- session's last compile content id
  booleans             <- from influence_class:
    used_and_changed_action    -> action_or_probe_changed=true, others false
    used_for_verification      -> verifier_changed=true
    prevented_repeated_failure -> repeated_failure_prevented=true
    suppressed_as_stale        -> suppressed_as_stale_or_wrong_scope=true
    suppressed_as_wrong_scope  -> same=true
    seen_but_not_used / loaded_without_delta -> all false
  cited_in_understanding_proof <- handle present in last submitted frame
  inclusion_or_suppression_reason <- "ack:" + influence_class
Anti-falsification unchanged: classes that claim influence still REQUIRE
downstream_outcome_ref (canon gate cognition.rs:300-310 untouched).
Test t_e8: ack with used_and_changed_action + outcome_ref -> stored full
record matches the derivation table field-for-field; ack claiming influence
without outcome_ref -> rejected exactly as today.
```

### E4.5 Honest memory-confidence echo (kills invented NO_USEFUL_MEMORY)

```text
recall/compile responses carry memory_confidence: found|weak|none computed
by the server (post-Librarian scoring). Skills instruct: never write
NO_USEFUL_MEMORY yourself; echo the server value via ack
(seen_but_not_used / loaded_without_delta) only. Removes the audit's
self-devaluation loop at the behavioral layer too.
```

## E5. Packaging per host

```text
E5.1 Codex CLI (hooks tier when the plugin exposes hooks; else tool tier):
  ~/.codex/config.toml        mcp_servers.eliot -> governor stdio (single entry)
  <repo>/AGENTS.md            append the E6.1 block verbatim (<=250 tokens)
  hooks (if supported by installed Codex version — capability-bind): map
  exactly to Part A WP7 (PreToolUse=pending lookup, PostToolUse=cue extract,
  PreCompact=handoff). No hooks -> Tier T piggyback covers it; AGENTS.md
  block is identical either way.
E5.2 Claude Code (hooks tier):
  .claude/plugins/eliot/  hooks/hooks.json:
    SessionStart -> eliot boot warm (server call, output suppressed)
    PreToolUse  matcher "Edit|Write|MultiEdit|NotebookEdit" -> inject
                pending_injection items as additionalContext (<=700 tokens)
    PostToolUse matcher "Bash|Edit|Write" -> extract cues from tool IO,
                enqueue firing (async, 0 output)
    PreCompact  -> request handoff artifact, emit as context
    Stop        -> if receipts show payload-injected negative memory with
                zero acks this task: single one-line reminder (never blocks)
  skills/ four SKILL.md per E6.2; .mcp.json single server entry.
E5.3 Claude Desktop (tool tier): MCPB bundle as audited; manifest description
  <=60 tokens; resource eliot://guide = one page (the E6.1 text + E4 cheat
  sheet); everything else is server-side (auto-boot, piggyback).
E5.4 Doctor: `ul doctor` verifies single registration, profile tool count,
  description budget, hooks presence, and prints PASS/FIX lines only.
```

## E6. Skill and guide texts (verbatim; supersede Part A WP7 skill wording)

### E6.1 AGENTS.md block / eliot://guide (shared core, <=250 ul-tokens)

```markdown
## ELIOT memory (read once)
Context arrives by itself: `ul_boot` on your first call, `ul_fired` on
responses, hook injections. Trust it. Never re-fetch what was injected;
expand handles only when your next action depends on them.
Work loop for material changes:
1. `eliot_compile_packet_l3 {goal}` -> read packet; edit `frame_stub`
   (intent, expected_observable, next step) and include it.
2. Do the change. On any error/test failure: check `ul_fired` for a matching
   episode BEFORE debugging from scratch.
3. Verify with the packet's `verifier`.
4. Save non-obvious lessons: `eliot_agent_candidate_submit {statement, kind,
   expected_reuse_note}` — bindings are automatic.
5. Ack memory you used: `eliot_memory_influence_trace {memory_handle,
   influence_class}` (+ `downstream_outcome_ref` if it changed your action).
Cost rules: omit optional fields; unsure about a form -> same call with
`dry_run:true`; on a validation error copy `minimal_valid_example`, fix the
listed fields, retry once; never invent NO_USEFUL_MEMORY — echo the
server's `memory_confidence`.
```

### E6.2 Claude Code skills (four; body <=500 each)

```text
skill eliot-work   desc "Material code change in an ELIOT project"
  body: the E6.1 work loop steps 1-3 expanded with one worked frame_stub
  example (fixture JSON, 5 edited fields highlighted) and the STALE-header
  rule: "[STALE ...] capsule => verify against code before relying".
skill eliot-remember desc "Save a lesson, decision or failure to memory"
  body: kind cheat-table (claim/decision/failure_fingerprint/skill: one
  trigger line each); the reuse question verbatim: "when will this matter
  again and what will be on screen at that moment?" -> expected_reuse_note;
  auto_bind explanation in 2 lines; dry_run tip; decision rationale fields
  (chosen_because / alternatives / revisit_when) with a 3-line example.
skill eliot-recover desc "A test failed or an error appeared"
  body: 1) look at ul_fired: matching episode? apply its fix path first and
  ack prevented_repeated_failure with the run ref. 2) none: write the
  observation (payload = normalized error), continue debugging; 3) after
  solving: submit failure_fingerprint (statement = symptom->cause->fix, one
  line each).
skill eliot-finish desc "Finishing an ELIOT task"
  body: run the packet verifier; ack every payload-injected item you acted
  on (class table inline); submit lessons; then stop — no summaries into
  memory, no restating the diff.
```

## E7. Adoption metrics (EVAL-ADOPT, server-computed from receipts)

```text
form_error_rate      = -32602 count / successful calls        target < 0.10
archaeology_incident = >=3 consecutive -32602 on one tool in one session
                       -> report_manifest UL-ARCH-{date} (must be 0 after E3)
boot_calls           = session_status+project_identity calls by worker
                       profile per session                    target ~ 0
ack_coverage         = payload-injected items acked / injected target >= 0.6
ritual_ack_guard     (counter-metric) acks for items never injected nor
                     fetched that session -> flagged, excluded from stats
write_adoption       = candidate_submits with auto bindings accepted
                       unedited / all submits (tracks E4.2 quality)
```

EVAL-ADOPT joins §7 families; B10 quarantine applies (post-Librarian data only).

## E8. Tests (extend D8 matrix)

```text
t_e1 description budget (E2)            eliot-app/tests/ul_e_surface.rs
t_e2 doubled-registry doctor detects a planted second entry, prints fix line
t_e3 dry_run: candidate_submit validates, writes nothing (row count, revision)
t_e4 auto-boot once per session (E4.1)
t_e5 field-name consistency lint over all published schemas
t_e6 auto_bind from touched-set (E4.2)
t_e7 frame_stub valid-except-one-field; 2 edits pass (E4.3)
t_e8 minimal ack derivation table exact; influence claim w/o outcome_ref
     rejected (E4.4)
t_e9 worker profile tool list == the 7 names of E1.2 exactly
t_e10 Stop-hook reminder fires at most once and never blocks (hooks tier)
```

Stage placement: E1–E4 implement inside UL-3 (they are the adoption face of first value); E5–E6 packaging lands with UL-5; EVAL-ADOPT with UL-6.

## E9. Closed decisions added to D10

```text
worker tools = the 7 of E1.2            descriptions = E2 verbatim pattern
boot = auto-attach, not tools           bindings = auto from touched-set
frame = stub-edit (<=5 fields)          influence = minimal ack + derivation
write_id optional (content-derived)     task_id optional (session-resolved)
guide/AGENTS text = E6.1 verbatim       skills = the four of E6.2
NO_USEFUL_MEMORY = server-echo only     dry_run on all writers
```

---

# Final statement

Governor made memory governed. The audit showed the implemented system is a superb **notary** of memory (provenance, fences, honest refusals) with a broken **librarian** (finding and delivering meaning). The remediation plan repairs the librarian's pull channel. UL adds the channel the librarian can never provide: **push by contact with the world** — memory written with triggers, fired deterministically when the agent touches the bound reality, organized as a small anchored ontology over three graphs, injected before action, paid for by saved exploration, and examined by prediction. The agent does not "use" this system — it works inside it, and its understanding of the project finally has both a habitat and a number.
