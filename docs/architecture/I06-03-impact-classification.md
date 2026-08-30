## I6.3. Impact classification

Governor computes baseline class from registered detectors. Agent may raise, never lower.

```text
Observe      — no state/effect;
Reversible   — local state, cheap deterministic rollback;
Material     — durable behavior/state/artifact or multi-file/module effect;
Critical     — security, authority, schema, destructive/external irreversible effect;
Forbidden    — policy excludes action regardless of rationale.
```

Mismatch between agent-declared and computed class creates Watchdog signal if repeated or suspicious.

