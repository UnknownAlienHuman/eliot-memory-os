## A13.8. Integrity

Periodic integrity review checks:

```text
canonical references and receipts;
ordering and epoch consistency;
provenance and dependency closure;
revocation and purge propagation;
Architecture digest and conformance map;
backup recoverability;
projection rebuildability.
```

It creates a Problem State and repair plan; it never resolves a semantic conflict silently.

External integrity anchors store a digest or identity, not a copy of semantic memory, and help detect rollback or history rewriting.

