## I12.29. Calibration aggregation and staleness

I12.18 owns per-action prediction capture and matching. This section owns only aggregation:

```text
aggregate by WorkScope/subsystem/task family and exact model-harness-route profile;
exclude `unresolvable` from hit/miss rates while reporting its frequency separately;
retain prediction/evidence lineage and sample distribution;
mark aggregate stale when verifier, route, Tool Definition, context policy or relevant environment profile changes;
use the result for routing/inquiry/Improvement Candidates, never as a scalar understanding authority.
```

