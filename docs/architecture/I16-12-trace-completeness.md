## I16.12. Trace completeness

A replayable Material/Critical trace requires:

```text
Task/Action contract and State Fence;
Active View/packet manifest;
principal, Session, leases and policy snapshots;
tool/model/module calls with inputs/outputs or immutable handles;
external-effect attempts and observed side effects;
verifier/artifact results;
canonical receipts;
finish decision;
missing parts explicitly listed.
```

Missing trace does not invent failure or success; it limits replay and may force `DEGRADED_NO_PROOF`.

