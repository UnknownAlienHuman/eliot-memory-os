## A7.10. Skills

A Skill should be concise:

```text
trigger;
intent;
immediate action;
required writeback or output;
stop or escalation;
where not to apply;
challenge path.
```

Deep semantics live in the Architecture, state, contracts, and tools. A Skill neither forces an agent to administer Memory OS nor serves as an enforcement boundary. For the Main Agent, the basic instruction kernel reduces to five actions: synchronize material state; report material observations, decisions, failures, and outcomes; act within visible authority; verify before claiming completion; challenge or escalate a false block. Conflicting instructions or Skills become explicit state and are resolved by source, authority, scope, and Intent—not by text order or the latest message.

**ARCH-SKL-01 — Instructions are intent-dense and recovery-oriented.** Few words, one meaning, a clear next step, and a clear exit from a false block.

---
