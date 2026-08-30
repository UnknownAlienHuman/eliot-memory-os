## I16.13. Influence tracking

Only observable influence is recorded:

```text
item delivered/expanded;
item cited in ActionFrame/decision;
item changed selected action/verifier;
item prevented exact failed path;
item used in DerivedCompletionProof;
item later shown irrelevant/harmful.
```

The influence ledger distinguishes:

```text
delivered;
acknowledged;
expanded;
cited/used;
changed action;
changed verifier;
prevented exact failure;
contradicted by user/tool/outcome;
ignored or bypassed;
counterfactual raw exploration cost;
observed context/tool cost.
```

Unknown acknowledgement or hidden model use remains `unknown`, never `unused`.

ELIOT does not claim access to hidden chain-of-thought. Success after inclusion is not automatically causal credit.

