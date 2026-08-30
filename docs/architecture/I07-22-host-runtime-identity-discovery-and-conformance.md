## I7.22. Host runtime identity, discovery and conformance

Discovery and conformance are separate:

```text
Discovery:
  find installation, hash executable/package, read version/help/manifest,
  create declared candidate profile.

Conformance:
  execute bounded operation probes, capture raw events/effects,
  classify failures, issue expiry-scoped capability evidence.

Production observation:
  confirm the same capability on the exact active fingerprint;
  detect route drift, cancellation failure, empty success and event loss.
```

An attempt may run with partially unknown actual-route fields only when policy permits. Unknown provider/model/billing identity cannot satisfy an independence claim, a provider-specific privacy claim, a billing claim or a route-specific verifier requirement. Observed route mismatch makes the result candidate-only, invalidates dependent capability evidence and normally quarantines that exact fingerprint pending reconciliation.

`--help`, README, model catalog and handshake booleans never grant production capability by themselves. Adapter admission requires exact scope-matching evidence and rejects stale/broken evidence.

No silent mid-attempt failover:

```text
before provider/runtime work begins:
  route may be retried or substituted under the same logical request;

after meaningful provider output, tool use or external effect:
  substitution creates a new attempt with a causal link and sealed handoff.
```

