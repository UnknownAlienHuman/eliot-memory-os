## A12.4. Source Assurance and Injection

A source is assessed on independent axes:

```text
identity and provenance;
integrity and freshness;
domain competence;
incentives and track record;
evidence independence;
privacy and sensitivity;
instruction-injection risk;
deception, exfiltration, and persistence risk;
allowed epistemic use;
allowed effects;
required verifier;
quarantine or review.
```

Instruction Taint asks whether content may command the system. Origin Assurance asks where an observation came from. Semantic Screening asks whether the content was checked for contradiction, overgeneralization, and hidden instruction. These properties remain distinct.

Embedded text never becomes an instruction by virtue of its content. An authenticated Human creates a new direct instruction record within their authority rather than "sanitizing" the source document. Suspicious material need not be deleted: it is isolated, retains provenance, and may be sent to Dreamer for semantic analysis and Watchdog for security analysis in a bounded bundle without elevated influence.

