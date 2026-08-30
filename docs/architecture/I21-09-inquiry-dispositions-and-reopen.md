## I21.9. Inquiry dispositions and reopen

Research/inquiry completion is also typed. An empty answer or exhausted search is not silently promoted to “question answered”:

```text
ANSWERED_WITH_SUPPORTED_RESULT;
NO_MATCH_IN_COMPLETE_SCOPE;
NO_NEW_USEFUL_EVIDENCE;
SOURCE_UNAVAILABLE;
STALE_SOURCE_OR_INDEX;
POLICY_OR_DISCLOSURE_DENIED;
INCOMPLETE_COVERAGE;
INCONCLUSIVE;
CANCELLED.
```

The disposition binds query, source portfolio, coverage denominator, reference manifest, State Fence and unresolved precision items. Only `ANSWERED_WITH_SUPPORTED_RESULT` or a properly scoped `NO_MATCH_IN_COMPLETE_SCOPE` may close the corresponding inquiry item; all other outcomes preserve a next probe, narrower claim or explicit unknown.

