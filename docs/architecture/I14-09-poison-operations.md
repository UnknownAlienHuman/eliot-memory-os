## I14.9. Poison operations

After bounded retries a deterministic/corrupt operation is dead-lettered with proven no-effect, opens a `SequenceGap` for its reserved position and creates or updates a quarantined Problem State.

```text
preserve operation identity/evidence/order;
pause only affected Ordering Scopes and declared dependents;
allow independent Ordering Scopes;
choose replace_same_identity, skip_proven_no_effect or cancel_dependents;
close the gap only through a canonical SequenceDisposition receipt;
never spin the whole writer lane indefinitely.
```

Operations rejected before sequence assignment consume no ordering position. Automatic endless retry and unaudited gap skipping are forbidden.

