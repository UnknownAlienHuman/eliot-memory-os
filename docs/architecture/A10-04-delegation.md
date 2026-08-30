## A10.4. Delegation

Every **Agent Work Unit** receives:

```text
one primary causal property and one primary owner;
an exact question and expected artifact or evidence;
a link to the current goal and acceptance criteria;
a frozen contract revision and applicable Architecture and Implementation handles;
minimally sufficient context: one-hop dependencies, known failures, and exact anchors;
read, write, and impact scope, allowed effects, and explicit non-goals;
the old failing behavior, representation gap, or missing capability;
a discriminator or verifier and proof ceiling;
role, authority, State Fence, budget, checkpoint, cancellation, and stop condition;
a structured output and integration owner.
```

"Small work" means causal closure, not a small number of files or lines. If one defect crosses several owners, decompose it into a contract or evidence unit, independent Module units, an edge or integration unit, and a Product Pulse; never give one agent a hidden cross-system mandate.

An agent may return a Contract Challenge when the selected owner is wrong, the discriminator measures a proxy, the contract is contradictory, or the required proof is unattainable within the granted scope. A challenge is not refusal and is routed to the Task Controller or Concilium.

Within one active task, exactly one Task Controller owns the current plan revision for the Authority Epoch. One mutable artifact scope has one writer; read-only research or audit lanes may run in parallel. Workers do not integrate their own results automatically: a separate integration owner revalidates the State Fence, affected edges, and product outcome. No shared mutable plan exists implicitly.

Goals, instructions, and constraints preserve source, authority, scope, and status: active, superseded, expired, or conflicting. A new instruction is not silently layered over an old one; an unresolved conflict limits only dependent actions and creates an interruption or reframing boundary.

