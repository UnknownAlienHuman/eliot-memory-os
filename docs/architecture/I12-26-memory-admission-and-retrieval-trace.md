## I12.26. Memory admission and retrieval trace

Candidate retrieval begins with deterministic known-handle lookup when a handle is supplied. Exact entity/path/symbol/error/task cues remain independently usable even when every graph is empty. The remaining routes are compiled into a `RetrievalPlan` from task, corpus, risk, freshness, coverage, latency and measured outcome/cost:

```yaml
RetrievalPlan:
  required_exact_routes:
  optional_routes: typed_relations | lexical | dense | graph | episode | Dreamer
  order_or_parallelism_and_reason:
  source_projection_fences:
  campaign_experience_query:
    campaign_or_task_family_scope:
    intent: NONE | FIND_SIMILAR_FAILURE | COMPARE_CANDIDATES | TRACE_DECISION |
            LOCATE_INFORMATION_LOSS | INSPECT_TOOL_LOOP | FIND_REGRESSION |
            FIND_PRIOR_SUCCESS | INSPECT_PARENT_LINEAGE | TEST_CONFOUND | RETRIEVE_RAW_SLICE
    exact_handles_and_filters:
    artifact_step_tool_error_and_metric_predicates:
    temporal_and_lineage_range:
    output_mode: INDEX | SUMMARY_WITH_HANDLES | DIFF | RAW_SLICE | GRAPH_NEIGHBORHOOD
    token_byte_and_time_budget:
    disclosure_retention_and_hidden-reasoning_fence:
  coverage_and_negative-claim requirements:
  budget_and_stop_conditions:
  fallback_or_abstention:
```

There is no universal `lexical → dense → graph` order. A hidden structural task may use a bounded graph route early; a known exact handle bypasses broad retrieval. `campaign_experience_query` is optional and `NONE` outside the applicable campaign/task-family scope. When present, it selects a bounded history slice from existing canonical attempt, memory, artifact, journal and Blob-handle owners; it does not create a `CampaignExperienceView` store, retain hidden provider reasoning or authorize full-history dumping. Every route remains subject to the same admission, disclosure, retention and proof ceilings, and its selected result/coverage handles are bound into `CampaignLearningStateView`.

`MemoryAdmissionDecision` evaluates:

```text
scope and State Fence;
epistemic status/freshness;
source assurance and allowed influence;
expected decision/information delta;
negative-memory/invariant/verifier value;
contradiction and framing risk;
token/latency cost;
repetition and distraction.
```

Outcome:

```text
include_exact;
include_handle;
include_with_warning;
require_revalidation;
suppress;
quarantine.
```

The associated `RecallDisposition` is a closed operational result, not a confidence scalar:

```text
ADMITTED_STRONG;
ADMITTED_WEAK;
NO_MATCH;
NO_USEFUL_MEMORY;
EMPTY_CORPUS;
SCOPE_SUPPRESSED;
STALE_PROJECTION;
CONFLICTED;
INCOMPLETE_COVERAGE.
```

It records scope and `TaskSelectionEvidence`, source/projection revisions and State Fence, freshness/coverage/assurance ceiling, visible and suppressed counts, route costs, a short agent-facing reason and the full rank-trace handle. Historical `LOW_CONFIDENCE` output maps to `ADMITTED_WEAK`; it is not a separate canonical disposition.

Before a retrieved candidate is projected or cited, coherent readback reopens the exact admitted source revision under the same `SourceView`, workspace-view revision and State Fence; verifies digest and byte length; resolves the requested anchor through its exact coordinate/native mapping; and verifies the selected unit or excerpt digest. Bytes currently present at a path cannot be cited as an earlier revision. Index/vector payload text may be shown as a non-authoritative preview, but citation and support require governed source readback. A missing revision, mapping or digest produces a narrower unsupported result, replan or typed gap—never a citation to convenient current bytes.

Before exact cue firing, source/projection revisions and the State Fence are compared. A mismatch yields `STALE_PROJECTION`, `PACKET_REFRESH_REQUIRED` or `PROBE_REQUIRED`; stale projection data is never silently injected into a Material decision.

Every material inclusion/suppression has `FusedRankTrace` or equivalent:

```text
candidates considered;
features and exact relations;
selected tier;
suppression reasons;
packet location;
dependency/invalidation set.
```

Vector similarity can nominate a candidate; it cannot create evidence, relation, blocker or causal status.

