## I5.18. Relation registry

Canonical relation families:

```text
supports / contradicts / verified_by / supersedes;
belongs_to / covers / implements / depends_on;
calls / reads / writes / produces / consumes;
causes / fails_because / resolved_by / invalidated_by;
blocks / unblocks / satisfies / reopens;
mentions / derived_from / included_in / used_for / suppressed_by;
authorized_by / assigned_to / influenced_by / invalidates_influence;
derived_disclosure_from / declassified_by;
grant_parent / introduced_as / bound_with_credential;
builds / emits_artifact / executes_test / covers_code / verifies_property;
co_change / resembles / diverges_from.
```

Every relation has:

```text
type and direction;
scope and time;
source/provenance;
epistemic status;
dependency/invalidation rule;
lifecycle and supersession.
```

`similarity`, `sequence` and `co_change` cannot be promoted to causal relation without a separate governed transition.

