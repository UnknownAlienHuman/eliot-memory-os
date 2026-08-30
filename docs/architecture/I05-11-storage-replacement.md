## I5.11. Storage replacement

```text
1. install candidate store bridge;
2. import snapshot into candidate;
3. verify counts, hashes, graph/projection invariants;
4. run shadow reads against both stores;
5. tail canonical events into candidate;
6. quiesce affected writes;
7. reconcile final sequence;
8. commit the `canonical_store` CapabilityRouteScope cutover through Kernel Generation Registry;
9. canary reads/writes;
10. keep old store read-only for rollback window;
11. retire only after backup and cutover receipt.
```

Rollback switches generation back only if no irreversible migration/effect occurred; otherwise uses forward repair.

