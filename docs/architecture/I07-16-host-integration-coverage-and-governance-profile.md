## I7.16. Host integration coverage and Governance Profile

`IntegrationCoverageProfile` records what a concrete host/adapter fingerprint actually exposes and enforces. `GovernanceProfile` is the Governor-derived vector used for authority and user-visible guarantees; it combines integration observation/enforcement with Watchdog supervision and trace freshness. Watchdog supplies supervision evidence but does not own the final profile.

Each integration profile declares each lifecycle/effect event as `ENFORCED | OBSERVED | EXPLICIT_OBSERVE | UNAVAILABLE`, plus completeness, pre/post-dispatch ordering, proof ceiling, source and gap evidence. Hook observation never mints authority. A profile based only on installed config or self-report remains unverified until host-observed events and effects match it.

Logical event set:

```text
SessionStart;
UserPromptSubmit;
SubagentStart;
PreToolUse;
PermissionRequest;
PostToolUse;
PreCompact;
PostCompact;
SubagentStop;
Stop/FinishAttempt.
```

Profile examples:

```text
EventIntegrated — lifecycle and tool outcomes visible; pre-action context/enforcement available;
ToolOnly        — only ELIOT calls visible; delivery is delayed/advisory;
ObserveOnly     — external traces visible, no reliable enforcement;
OfflineWorker   — bounded input/output job with no live host events.
```

The integration profile records actual runtime coverage, not only installed configuration. Missing events update the corresponding observation/enforcement axis; Governor then derives a new revision-bearing GovernanceProfile and revokes authority that depended on the lost guarantee. No component replaces the vector with a single marketing grade.

