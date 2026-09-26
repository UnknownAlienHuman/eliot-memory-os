# Code-complete remediation

Non-normative, bounded work brief. The linked issue comments own the exact reviewed source, counterexamples, limitations and acceptance advice. This brief neither changes architecture nor closes an issue. Retire it when the listed repairs are reconciled.

## Repair scope, in original issue creation order

| Issue | Required code/configuration repair | Check after the repair is built |
|---|---|---|
| [#8](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/8#issuecomment-5811313486) | In the agent bridge bootstrap path, obtain readiness and task selection from the authenticated owner; do not trust host-authored readiness, principal, scope or fence. Bind the exact current task revision and acceptance digest. Auto-bootstrap must use the same owner snapshot. | Forged/stale/cross-session evidence, no task, ambiguity, zero revision and missing acceptance cannot produce `READY`. |
| [#10](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/10#issuecomment-5811346583) | In `eliot-store-api::payload_authority`, give unverified pre-fix records an explicit unknown/non-authoritative disposition. Absence of a known corruption signature is not proof of preservation. Reconstruct from exact source or positively established intact evidence. | Unsupported multi-colon forms at the root and inside arrays/objects cannot become `PreservedIntact` or an authoritative replay without the required evidence. |
| [#18](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/18#issuecomment-5811374059) | Complete current Codex MCP and Claude Desktop manifest cutover to their declared owners. Do not merely rename the executable. Replace the constant-shape `assert_no_new_ownership` check with validation tied to actual registrations/consumers, or stop claiming it enforces ownership. | Production packages select current-owner protocols; undeclared legacy consumers and forbidden ownership additions fail the appropriate check. |
| [#19](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/19#issuecomment-5811449899) | In the Surreal adapter evidence-read boundary, keep unknown erasure status fail-closed for disclosure but report indeterminate/unavailable coverage, not a complete zero-match success. | Transport/query/decode failures with an existing capture withhold bytes without asserting `matched_total=0` and complete coverage. Confirmed-empty controls remain distinct. |
| #66 | No new confirmed defect in the reviewed typed projection, daemon submit/reconcile and Kernel retention paths. Do not revive the obsolete success-only error-swallowing diagnosis. This is not full acceptance approval. | Preserve exact-result replay, typed selection/failure outcomes, stale-fence denial and deadline/retention behavior during the planned acceptance phase. |
| [#77](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/77#issuecomment-5811506698) | Replace the production event forwarding/reconciliation stubs with the admitted observation/ORS owner path. Keep events distinct from Invoke/Cancel and do not create a bridge-owned durable ledger. Until then, report the missing capability rather than an impossible reconcile-then-retry remedy. | Owner-issued durable acknowledgement, lost-ack reconciliation, changed-payload rejection and authorized reconnect cursors work through the actual event path. |

## Allocation and completion

Keep repairs under their existing owning issues and use finite source allocations. Serialize #8/#77 writers where bridge files overlap. Complete each #18 consumer's required current-owner protocol before switching its manifest; a compatibility fixture is not a production cutover.

Implement code/configuration first and build the repaired product. Then run the applicable focused regression checks and scheduled Product/Windows/Surreal acceptance. Missing implementation stays code work; an implemented path awaiting execution evidence may remain in the test phase. Never convert a missing owner, unknown data state, or constant-only check into a successful acceptance claim.

Keep execution evidence in issue/PR discussions or CI artifacts, not in this brief. Review remaining `is:issue state:open label:code-complete` items oldest-first; this scope stops at #77 and the next unreviewed issue in the captured queue is #196.
