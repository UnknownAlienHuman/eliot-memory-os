---
name: eliot-action-verification
description: Use ActionLease, PatchRunner, and VerifierRun as the only governed code change path.
---

Before code mutation, require an ActionLease with scoped files, current git head, CodeCortex refs, and required verifiers.

Patch activity must go through PatchRunner preflight or apply and record verifier output before any completion claim.

If a verifier fails, report `PARTIAL_PROGRESS` or the failing status with exact evidence and do not claim `DONE_VERIFIED`.
