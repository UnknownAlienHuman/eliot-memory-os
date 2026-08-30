## A11.3. Capability Registry

The Registry stores observed capability:

```text
installation identity and version;
transport, lifecycle, hooks, and tool coverage;
model route, cost, privacy, and availability;
competence and context profiles;
verifier validity and freshness;
failure-domain and evidence-independence profile;
known biases and failure signatures;
health and allowed WorkScopes and principals.
```

Profile dependencies include model and provider version, inference regime, harness, Tool Definitions, context policy, evaluator, and relevant data distribution. A change to any of them makes dependent profiles provisional until requalification.

