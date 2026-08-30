## I12.35. Multimodal, object and workflow continuity

ELIOT preserves continuity across code, documents, images, audio/video, GUI state, services and professional workflows without pretending that a text summary is equivalent to the source modality.

`ContinuityObservation` contains:

```text
source/modality and exact temporal/spatial/byte/range anchor;
source checksum, capture route and representation limits;
entity/object identity hypotheses with confidence and contrary evidence;
before/after StateDiff and affected workflow step;
relations to task, artifact, service, participant and verifier;
raw/derived handles and loss warnings.
```

`WorkflowStateView` tracks:

```text
workflow identity, current/previous step and owner;
inputs, outputs, pending commitments and external effects;
expected observable and verifier;
interruption/resume boundary and idempotency;
artifact lineage and unresolved representation gaps.
```

Identity is type-relative: a rename, crop, render, export, restart, merge or split may preserve one kind of identity while changing another. ELIOT stores competing continuity hypotheses rather than merging by filename or semantic similarity.

When a modality-competent observation/evaluator is absent, the property remains unknown or degraded. A model-generated textual description is a derived candidate and cannot prove visual, acoustic, spatial or interaction properties that it did not measure.

---

