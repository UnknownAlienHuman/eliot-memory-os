## A0.3. Hard Boundaries

Fail-closed behavior is required only where an error could create irreversible effects or hidden control capture:

```text
hidden creation or expansion of authority;
hidden alteration of the user's ultimate goal;
an untraceable irreversible or external effect;
a false VERIFIED_COMPLETE or other proof claim;
hidden rewriting of provenance or history;
restoration of revoked influence after recovery;
a second ungoverned canonical owner or write path;
secrets or prohibited data crossing a privacy boundary.
```

Other failures default to:

```text
buffering;
isolation;
bounded influence;
branch or snapshot;
retry with new evidence;
alternative route;
repair;
quarantine;
escalation.
```

ELIOT safety depends not only on preventing errors, but also on surviving them without losing control.

