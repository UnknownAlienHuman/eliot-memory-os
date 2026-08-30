## I4.6. Change detection

Sources:

```text
filesystem watcher (`notify`) as hint;
Git reconciliation as authoritative code change summary;
process/service health;
remote ETag/version probe;
editor/host event;
module outbox event;
manual Human declaration.
```

A watcher event is not a canonical fact by itself. It starts bounded reconciliation.

A change:

```text
increment affected resource generation;
invalidate dependent views and leases;
mark derived capsules/graphs dirty;
keep independent scopes active;
queue context delta and attention if material.
```

Every current-state observation carries an orthogonal freshness value:

```yaml
observation_freshness: current_confirmed | observed_with_age | gap_detected | unknown
```

A watcher/USN overflow, missing cursor interval or unresolved editor-overlay gap prevents the claim “current workspace state”. The system reconciles within budget or returns `OBSERVATION_GAP`; it does not relabel an old index as current. A bounded non-strict read may use `observed_with_age` only when the age and limitation are exposed. Exact absence, completeness and current-state claims require `current_confirmed`. Historical/frozen views may deliberately use retained immutable bytes and state that view explicitly.

