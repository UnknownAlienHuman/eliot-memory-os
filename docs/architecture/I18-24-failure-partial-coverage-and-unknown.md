## I18.24. Failure, partial coverage and unknown

Testing outcomes are not binary when evidence is incomplete:

```text
PASS        — property proven in declared scope;
FAIL        — contradictory observation or missing required stage;
PARTIAL     — some required scope measured, some explicitly uncovered;
UNKNOWN     — tool/parser/freshness/coverage cannot answer;
BLOCKED     — policy/environment/capability prevents required proof;
CANCELLED   — no further effect; prior evidence retained.
```

`UNKNOWN`, `PARTIAL` and `BLOCKED` never become PASS through aggregation. FinishService maps them to task outcomes using acceptance criticality and authority; InstrumentRunner does not decide completion.

