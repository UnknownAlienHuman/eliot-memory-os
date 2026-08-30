## I12.34. Cognitive proof ladder and ecological field proof

A lower proof level is not elevated by suite name or a polished report:

```text
TransportProof
  bytes/record crossed the intended boundary;

RetrievalProof
  correct scoped item was found and delivered;

UseProof
  agent demonstrably referenced it in a decision/action/verifier;

DecisionDeltaProof
  treatment changed first boundary, unknown, verifier or avoided failure;

OutcomeBenefitProof
  changed decision improved real artifact/verifier outcome
  relative to a matched control or strong counterfactual;

RetentionProof
  benefit remains after the declared delay/restart/requalification window
  and preserved previously verified behavior does not regress;

TransferProof
  benefit survives revalidation on a new declared scope, task or route.
```

Different claims have different ceilings. A task-local correction may legitimately stop at `UseProof` or `DecisionDeltaProof`. A reusable Skill, procedure, or system policy is not promoted without `OutcomeBenefitProof` and `RetentionProof`. A general portability claim requires `TransferProof`.

Intermediate learning states form neither a second ladder nor one aggregate status. Their lineage is typed: capture and interpretation use `AttemptLearningDelta`; admitted adaptation uses `CampaignHarnessOverlay`; eligibility, retrieval, delivery, observable activation, and adherence use exact per-attempt `HarnessActivationReceipt`; campaign disposition uses `CampaignLearningClosure`; aggregated Skill history uses `SkillLifecycleView`; execution, evaluation, and attribution use applicable `EvidenceStatus` fields. These records explain why a proof step was or was not reached, but do not elevate it by themselves.

A receipt with `retrieval.status = RETRIEVED | EXPANDED` and `delivery.status = FULL`, but `activation.status = NOT_ASSESSED | NOT_OBSERVED | UNKNOWN`, proves only bounded retrieval and delivery—not `UseProof`. `activation.status = OBSERVED` requires `first_qualifying_observable_use_ref` and proves only observable use at the declared boundary; acknowledgement is insufficient. Even observed activation proves neither adherence, decision delta, attribution, nor benefit. Exact-handle read is a forensic capability. Marker recovery is not project understanding.

Product-level Understanding acceptance uses an ecological A/B field test:

```text
fresh agent and real unseen task;
no marker, answer terms, exact handle or prescribed retrieval query;
automatic correct WorkScope/task binding;
one useful prior decision/failure in memory;
world/task contact delivers memory before Material action;
agent publishes causal model, rival/unknown and expected observable;
real verifier checks the artifact/effect;
matched memory-free control uses the same model/harness/tools/task family;
primary outcomes: first-boundary correctness and artifact/verifier result;
next independent session reuses the lesson after restart;
tokens, calls and latency are counter-metrics.
```

A suite/harness can be accepted as evaluation infrastructure without the product passing it. Reports must state this distinction explicitly.

