## I20.5. Researcher providers and external federation

Researcher is defined in I21. This section states only the replacement boundary of its providers.

```text
P1  manually or bridge-supplied sources
    current accepted line; no additional runtime required;

P2  local search/preparation provider
    separate product and repository; owns source identity/revisions, safe reads,
    materialization, unitization and exact/lexical/structural/semantic projections;
    reached through a typed provider contract, never through canonical credentials;

P3  external research federation
    separate product and repository; owns large corpora, acquisition/OCR/indexing,
    long-running investigations and research publications;
    reached through the current `ResearchExchangeContract` of I21.11.
```

For every admitted source namespace, exactly one component is the authoritative mutable owner of source identity and source revisions. The local provider owns local source namespaces it ingests; an external federation owns its own namespaces; a manual import remains owned by the importing source adapter until an explicit cutover. ELIOT canonical state owns admission, handles, provenance, and allowed influence—not mutation of provider source history. Researcher, Dreamer, Context Compiler, Memory OS, and other providers hold immutable references or derived projections only. Provider replacement requires an explicit source-owner cutover with identity mapping, fencing, compatibility verification, and a receipt; a second mutable source catalogue or revision lineage is prohibited.

No provider is required for the first cognitive spine. A provider supplies candidates, coverage and freshness; it never receives task authority, canonical write access, Context Compiler admission or finish authority. Absence or failure of a provider narrows declared coverage and is reported as a gap; it does not stop the core hot path and does not transfer its responsibility to Dreamer.

A provider is replaced through its own contract, conformance corpus and capability descriptor. Replacing a provider never changes Researcher semantics, evidence grade, dispositions or coverage accounting.

