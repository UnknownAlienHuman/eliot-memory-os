## I15.7. Bounded influence

Even admitted content has effect limits:

```text
may appear as evidence/hypothesis;
may be excluded from instruction/procedure/policy;
may require independent verifier;
may be quarantined from agents but retained for forensics;
dependent influence can be revoked.
```

Final-result filtering is defense in depth, not an access-control boundary. Content that was unauthorized or revoked may already have influenced candidate generation, rank/IDF statistics, counts, diversity, summaries or traces. If such content participated in a retrieval/scoring branch, the whole contaminated branch—including dependent synthesis/model work—is discarded and replanned under the latest grant/policy; deleting only forbidden candidates cannot sanitize the ordering or erase prior influence. A branch proven not to have touched the revoked population may remain. If safe re-execution cannot finish within budget, the result returns the applicable denial/revocation reason and `INCOMPLETE_COVERAGE`, exposing none of the contaminated ranking.

