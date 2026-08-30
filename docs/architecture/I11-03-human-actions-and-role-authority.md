## I11.3. Human actions and role authority

The Control Plane exposes actions by authenticated role; “Human” is not one undifferentiated superuser.

| Human role | Normal actions |
|---|---|
| Requester / Domain Owner | define/clarify/supersede user outcome and acceptance; set task cost/risk preferences; accept or reject the claimed user outcome |
| Architecture Owner | inspect and accept/supersede Architecture revisions |
| System Owner / delegated Operator | start/stop ELIOT; manage routes/models, Module Catalog policy, ordinary module generations, backup and migration within delegation |
| WorkScope Owner | open/close/narrow WorkScope; set scope privacy/retention/risk and applicable verifier contracts |
| Approver | approve/deny one exact Critical action hash |
| Recovery Principal | execute one predeclared bounded break-glass/recovery transition |
| Any authorized role | inspect evidence/receipts, request Dreamer/Watchdog analysis, acknowledge notifications; resolution still requires the role that owns the underlying state |

Task Controller assignment, swarm launch/stop, Improvement Candidate disposition and problem/attention resolution are allowed only when the caller holds the corresponding task, budget, policy or state-owner capability. UI must state consequences, affected scope, expiry and current authority—not display raw internal IDs alone or offer a button the principal cannot lawfully execute.

