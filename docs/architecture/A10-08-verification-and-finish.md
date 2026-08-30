## A10.8. Verification and Finish

Finish states:

```text
VERIFIED_COMPLETE;
PARTIAL;
BLOCKED;
FAILED_VERIFICATION;
DEGRADED_NO_PROOF;
UNSAFE_TO_FINISH;
CANCELLED;
SUPERSEDED.
```

Only `VERIFIED_COMPLETE` is called a completed task. Other states honestly preserve artifacts, effects, gaps, and continuation.

Professional work is confirmed by an artifact, admissible method and environment, and an appropriate evaluator—not by plausible prose. An artifact may be code, document, spreadsheet, report, image or video, GUI state, service, or research result; proof matches its modality and required shape.

**ARCH-FIN-01 — Completion is proof-bearing.** ELIOT supports progress under incompleteness but never turns partial progress into done.

---
