## A12.6. External Model Routes and Secrets

A model job contains a question, bounded inputs, State Fence, privacy class, route class, budget, deadline, allowed effects, cancellation, and receipt.

Secret and credential lifecycle:

```text
minimum scope visibility;
no transmission to a model, logs, or memory without explicit need;
rotation or revocation after compromise;
no command-line or plaintext leakage;
backup and restore at the same privacy level;
human confirmation before expanding external transmission.
```

Provider fallback never expands data access or cost silently. Provider-native memory is treated as an external source or feed with its own retention and deletion semantics; it does not become a canonical owner, policy, or current support without normal ELIOT reconciliation.

**ARCH-SEC-04 — Model output remains a candidate until a governed transition accepts its effect.** A model role, number of agreeing routes, or confident format creates no authority, factual support, or completion.

Remote Dreamer is a separate external principal and read-oriented semantic surface. It receives no local tools, database handles, write authority, or agent-launch authority.

