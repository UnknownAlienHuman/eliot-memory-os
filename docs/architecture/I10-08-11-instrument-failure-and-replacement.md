### I10.8.11. Instrument failure and replacement

Each parser, profile, executable adapter and optional code-intelligence backend is a micro-module under I2.16. Failure localizes to the affected profile/stage:

```text
required instrument unavailable
  → profile partial/failed with explicit missing proof;

optional instrument unavailable
  → reduced coverage and typed unknown;

parser incompatible
  → raw evidence preserved, normalized result unavailable;

process cleanup failure
  → Problem/Incident, route quarantine and no false pass;

stale code index
  → stale evidence; no negative fact;

replacement
  → new immutable tool/profile/parser generation, golden contract tests,
     shadow/canary and revisioned cutover.
```

Instrument evidence never outlives its executable, config, candidate and parser dependency set without revalidation.


