---
name: eliot-task-cycle
description: Use Eliot governed task phases from grounding through verification and closeout.
---

Run the smallest current verifier before changing code, keep phase closeouts current, and treat `DONE_VERIFIED` as the only final success state.

For code tasks, start with CodeCortex scan evidence, then create any ActionLease or PatchRunner activity only through governed Eliot commands.

Do not use ungoverned patch, shell, search, database, or file surfaces when an Eliot MCP or CLI command covers the workflow.
