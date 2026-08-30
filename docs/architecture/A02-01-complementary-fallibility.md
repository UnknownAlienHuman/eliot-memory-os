## A2.1. Complementary Fallibility

| Participant | Strength | Typical failure |
|---|---|---|
| Human | Goals, values, context, legitimate authority | Incomplete knowledge, fatigue, conflicting preferences |
| Main Agent | Semantic synthesis, plans, alternatives | Hallucination, framing error, context loss, rationalization |
| Deterministic tool | Exact measurement of a defined property | Narrow competence, misconfiguration, absence of meaning |
| Governor | State, authority, lifecycle, receipts | Incomplete observability, implementation defect |
| Dreamer | Broad synthesis and hypothesis generation | Smooth false narrative, correlated model bias |
| Watchdog | Independent process and security observation | False positive, incomplete coverage |
| Verifier | Scoped proof | Wrong construct, stale environment, blind spot |

**ARCH-ROLE-01 — Authority is separated by function.** Observation, interpretation, authorization, and verification should not belong to one participant without necessity.

**ARCH-ROLE-02 — Responsibility follows competence and failure type.** No Human, model, or tool is a universal oracle.

**ARCH-AUTH-01 — Authority is explicit, scoped, and fenced.** Content, model confidence, and role names never create a right to perform a transition or effect; authority has an owner, scope, State Fence, and revocation path.

