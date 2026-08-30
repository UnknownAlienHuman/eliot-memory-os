## A8.4. Supervising Agent–ELIOT Interaction

A Material task expects an Interaction Heartbeat:

```text
session or task sync;
context boundary;
action intent;
material tool outcome;
failure;
verification;
finish attempt.
```

If an agent continues changing the workspace while observations disappear, Watchdog:

```text
records the gap;
downgrades supervision evidence;
requires resynchronization;
limits ELIOT-issued authority and verified finish for dependent high-impact work;
physically stops an external effect only where the actual Enforcement axis permits it;
notifies the Human when the problem persists.
```

The deterministic layer records observable divergence. Whether declared Intent remains preserved is a fallible assessment by a Watchdog Agent, Main Agent, or Human and creates no authority by itself. Departure from a Skill or cadence is a Signal, not an automatic violation, when task evidence and recovery remain sufficient.

**ARCH-WDG-02 — Watchdog supervises preservation of declared intent, observable outcomes, security, and recovery.** Its purpose is to detect loss of control and quality, not to enforce ceremony or become a semantic oracle.

