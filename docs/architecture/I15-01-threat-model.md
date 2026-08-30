## I15.1. Threat model

Assume:

```text
agent/model can hallucinate or ignore instructions;
external content can contain injection;
Tool Definitions can be poisoned;
module/bridge can be buggy or compromised;
agent can attempt direct storage/process bypass;
credentials can leak through logs/env/command line;
stale process can continue after restart;
backup can restore revoked/erased influence;
Human can make mistakes;
security detector can miss attack or false-positive.
```

