## I7.27. Evidence execution, parsing, evaluation and independence

One `passed` boolean is forbidden. Instrument/model/tool evidence carries orthogonal status:

```yaml
EvidenceStatus:
  execution: NOT_EXECUTED | SIMULATED | EXECUTED | UNKNOWN_OUTCOME
  parsing: RAW | PARSED | PARSE_FAILED | NOT_APPLICABLE
  evaluation: UNASSESSED | PASS | FAIL | INCONCLUSIVE | STALE
  independence: SELF_REPORTED | SAME_PATH | SAME_ROUTE_NEW_PROMPT |
                DISTINCT_MODEL_SAME_EVIDENCE | DISTINCT_OBSERVATION_ROUTE |
                DISTINCT_IMPLEMENTATION_OR_TOOLCHAIN | DISTINCT_FAILURE_DOMAIN |
                DISTINCT_ANALYST_OR_TEAM | HUMAN_OBSERVATION | INDEPENDENT_FORMAL_CHECKER
  artifact_binding: UNBOUND | BOUND_EXACT | BOUND_PARTIAL
  attribution: OBSERVED_ASSOCIATION | SUPPORTED_CONTRIBUTION | OBSERVED_UNDER_INTERVENTION |
               COMPOSITE_BENEFIT | CONTRADICTED | UNKNOWN
  scope_and_state_fence:
```

Independence is a non-ordinal failure-domain profile, not a proof ladder. It names what actually changed; multiple labels may apply. A different prompt on the same route is the weakest variation and never satisfies an independent-verification requirement by itself. A different model that shares the same evidence, parent context or evaluator remains dependent on those domains, and no independence label proves correctness.

`attribution` asks not “was a result obtained?” but “was the mechanism demonstrated?” A composite change may legitimately be used operationally as `COMPOSITE_BENEFIT`, but its narrative explanation is not a demonstrated mechanism without separation or control.

Synthetic plan/profile records use `NOT_EXECUTED`; they may test shape and scheduling only. A real verifier requires `EXECUTED`, exact executable/config/artifact identity, immutable raw evidence handles and an applicable Evaluation Contract. Parser success is not execution; execution is not independent verification; independence is not correctness.

