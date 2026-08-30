## I14.10. Supervision strategies and restart intensity

Erlang-style supervision is explicit in Module/daemon manifests; it is not inferred from process-tree shape.

### Child restart class

```text
permanent
  restart after any exit unless the owner is quiescing or retiring it;

transient
  restart only after abnormal exit or failed health contract;

temporary
  never restart automatically; preserve outcome/evidence and let the owner decide.
```

### Group strategy

```text
one_for_one — DEFAULT; restart only the failed independent child;
rest_for_one — restart the failed child and explicitly declared downstream
               dependents whose operational state or fence became invalid;
one_for_all — restart one small declared supervision group only when its members
              share inseparable operational state and independent recovery is unsafe.
```

Startup order alone does not define `rest_for_one`; the manifest dependency/invalidation graph does. `one_for_all` may not include Kernel, canonical store, Watchdog or unrelated Modules and requires a measured failure reason.

Every supervised child has a bounded restart-intensity window, backoff, cooldown, stable-uptime reset condition and quarantine threshold. A restart attempt records exit evidence, generation, State Fence, resource state and unresolved effects. Exceeding the intensity budget stops automatic restart, opens or updates Problem State and moves the child/group to `QUARANTINED` or `MANUAL_RECOVERY`. Restart restores liveness only; it never resolves the underlying Problem State without verifier evidence.

