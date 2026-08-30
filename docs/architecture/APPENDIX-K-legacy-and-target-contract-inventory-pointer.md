# Appendix K. Legacy and target contract inventory pointer

> **Status:** non-authoritative pointer. The former manual inventory has been preserved in a content-addressed cold evidence artifact and removed from the normative book; its extraction lineage records the one de-duplication change relative to the frozen 0.22 base. It was useful for donor retirement and migration vocabulary, but its continued inline presence created a second schema-like surface, prompt cost and a hidden implementation backlog.

Current rules:

```text
owning I-section
  → meaning, owner, behavior and failure semantics;

accepted generated ContractCatalogueEntry / IDL
  → field-level executable contract;

physical schema and Rust interface projections
  → Appendices N/P, TARGET until exact code/tests prove support;

cold legacy/target inventory
  → historical discovery only, loaded by exact handle for migration or archaeology;
  → never part of normal agent hotset, conformance proof or work-item generation.
```

A contract absent from the accepted catalogue remains `TARGET` or `CURRENT_UNVERIFIED` even if an old YAML example exists. Donor name-level dispositions remain in the content-addressed retirement ledger; active behavior is always resolved through the current owner.

