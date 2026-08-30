## I8.15. Watchdog generation replacement

Watchdog is outside Kernel's child tree, so its replacement is controlled through SCM/Host rather than the Module route table.

```text
1. stage immutable candidate service artifact and manifest;
2. start the candidate under a temporary SCM service identity or equivalent installer-owned
   shadow process, with a separate candidate spool and zero containment authority;
3. compare sensor coverage, signal normalization, anchor continuity and resource use;
4. publish an explicit temporary supervision-degradation notice if a gap is unavoidable;
5. installer/SCM performs one observed activation change and issues a new supervision epoch;
6. only after activation may the candidate request containment; drain/stop the old service;
7. retain the previous compatible artifact and spool reconciliation receipt.
```

Two Watchdog generations may observe simultaneously, but only one active supervision epoch may request containment. Duplicate signals deduplicate by evidence identity and observation route; agreement of two generations is not independent evidence when they share sensors.


