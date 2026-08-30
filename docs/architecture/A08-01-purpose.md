## A8.1. Purpose

Watchdog is a separate daemon in an independent failure domain. It operates continuously and independently **during every declared active ELIOT interval**: while there is an observable Session or agent job, active work in a registered WorkScope, a maintenance or recovery operation, an external effect under supervision, or a supervision policy explicitly enabled by the user. When ELIOT is unused and no such obligation exists, Watchdog and the other processes may stop after preserving observation cursors, unresolved control state, and future wake intent. This does not weaken supervision: the system claims coverage only for the active interval it actually observes and exposes blind gaps explicitly.

It observes whether the ELIOT contour operates as declared:

```text
whether Kernel, Governor, Doctor, hooks, and integrations are alive;
whether ELIOT can observe agent actions;
whether observations and outcomes are arriving;
whether one failure repeats without new evidence;
whether the canonical path is bypassed;
whether queue pressure, stale state, or repair loops are growing;
whether a security, injection, or exfiltration signal appeared;
whether Architecture, Implementation, and runtime diverge.
```

Watchdog does not decide project semantics, task goal, factual conflicts, policy, or completion.

**ARCH-WDG-01 — Independent supervision.** At least part of liveness, process, workspace, and integration activity is observed outside Governor and primary-agent self-report throughout every interval for which ELIOT claims independent supervision. Observable use activates this contour; outside an active interval, an inactive Watchdog is not presented as observation or coverage.

