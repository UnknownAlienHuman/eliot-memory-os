## I0.7. Documentation-cycle stopping rule

Implementation is sufficiently defined for code work when:

```text
an owner exists for every process and mutable state;
the protocol and failure behavior of the first vertical spine are defined;
there is no hidden second write path;
the system can be built, started, verified, and stopped;
a local change has a clear affected-test path;
unknown details are marked as a Research Gate rather than disguised as guesses.
```

The document need not define every data structure in advance. A concrete structure appears when required by the next layer.

After these conditions are met, new prose is allowed only when it closes an unresolved decision in the next executable slice. As implementation proceeds, wire schemas, error registries, state tables, test inventories, compatibility matrices, and contract indexes move to generated artifacts; the book retains rationale, owners, failure behavior, and links.

`ContractSurfaceProfile` measures not “document quality” with one number, but operational cost:

```text
number of contracts actually applicable to one work unit;
serialized instruction/contract token cost;
number of expansion handles and stale projections;
change fan-out of one contract;
orientation time and Contract Challenge frequency;
agent errors caused by conflicting or overloaded instructions;
share of prose already duplicating executable schema or code.
```

Growth of this surface without Product or Recovery delta triggers simplification, merge, or generation review—not another documentation campaign.

---

