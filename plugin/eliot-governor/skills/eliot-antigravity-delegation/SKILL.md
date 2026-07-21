---
name: eliot-antigravity-delegation
description: Route a bounded external review from Codex through Eliot Governor to Antigravity. Use for Antigravity, second opinion, external review, independent audit, risk review, architecture review, diff review, verifier suggestion, repeated failure, or when verifiers disagree.
---

# Govern Antigravity delegation

Use `eliot_delegate_review` for normal Antigravity delegation. Always call it when the user explicitly asks for Antigravity unless the tool returns a concrete denial. Never call raw `agy`, raw `agy-mcp`, or an Antigravity execution tool.

1. Keep the question bounded and independent. Ask for candidate findings only.
2. Require the current active `work_lease_id`. Do not create the disposable worktree manually; Governor owns its creation and cleanup.
3. Set `origin` to `user_directed` for an explicit user request, `codex_requested` for a strong trigger, or `policy_shadow` for no-execution calibration.
4. Choose only `architecture_audit`, `risk_review`, `diff_audit`, or `verifier_advice`.
5. Use `eliot_delegate_status` and `eliot_delegate_result` with the returned delegation id.
6. Treat every result as candidate-only and externally tainted. Reconcile it with controller decisions and verifier evidence before acceptance.

Codex may call it once for a security or authority boundary, uncertain external integration, second repeated failure, verifier disagreement, high-impact diff, or evidence gap blocking completion. Do not call it for formatting, trivial deterministic fixes, or duplicate fresh reviews.

Stop on a denial. Never retry a valid low-quality response, expose secrets, request provider implementation, call Antigravity from an Antigravity-originated request, or treat Antigravity output as verified truth.
