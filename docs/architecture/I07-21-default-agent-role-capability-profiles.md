## I7.21. Default agent role capability profiles

Profiles are defaults compiled into Capability Tokens; WorkScope policy may narrow them. A role name never grants more than the issued token/lease.

| Role | Normal operations | Mutation ceiling | Required authority | Explicitly forbidden |
|---|---|---|---|---|
| **Requester / Domain Owner** | goal, acceptance, value, task-level risk/cost preferences, outcome evidence | revise or supersede the `UserOutcomeObjective`; accept/reject the claimed user outcome | authenticated role or exact delegated goal/acceptance capability | factual proof, Architecture or installation policy by preference alone |
| **Main Agent** | state, packet, query, observe, act, verify, propose coordination/finish | content decisions, candidates, action/finish attempts inside delegated task authority | task role capability; Action Lease for effects | changing user goal, current plan ownership unless separately Task Controller, schema/admin, self-verification outside Evaluation Contract, direct truth/policy promotion |
| **Task Controller** | state, work graph, plan, agents, conflicts, budgets inside the delegated task envelope | current plan revision, assignment/reassignment, bounded task disposition proposals | active TaskController lease/epoch | redefining user outcome, Architecture/policy, factual proof, Module deployment authority, executing effects without Action Lease |
| **Worker** | state, packet, query, observe, coordinate; `act` only for assigned item | evidence, observations, candidate result, lease-covered effect | Work Lease; Worktree/Action Lease when mutating | task finish, active-plan overwrite, policy/schema, unrelated paths |
| **Auditor / Challenger** | state, packet, query, observe, coordinate | audit finding, counterevidence, conflict/challenge candidate | read/audit capability for exact scope | live-tree or external effect, truth promotion, task finish |
| **Verifier Agent** | state, query, verify, observe | scoped evaluation candidate or VerificationRun for registered verifier IDs; verifier artifacts | Verifier capability + Evaluation Contract | redefining acceptance/verifier, implementing the fix it judges unless roles are explicitly separated and independence is downgraded |
| **Synthesis Agent** | query, packet, coordinate, observe | lineage-preserving synthesis candidate | aggregation work item | majority vote as proof, dropping dissent, canonical decision/finish |
| **Curator / Dreamer Agent** | bounded job resources; no general live tool surface by default | curation/research/memory transformation candidates | Dreamer job + budget/privacy policy | direct canonical write, policy/authority/epistemic promotion |
| **External reviewer** | bounded packet/evidence/artifact bundle | candidate findings or patch in scratch worktree | ExternalReviewRequest | local DB, live tree, secrets, finish/approval |
| **Architecture Owner** | accepted Architecture, rationale, conflicts and evidence for change | accept/supersede an Architecture revision | authenticated Architecture Owner role | runtime facts, project outcome or implementation support without evidence |
| **System Owner / delegated Operator** | installation, route/model availability, Module Catalog policy, services, backup and ordinary migration | policy-covered infrastructure/config/module-generation transition | authenticated System Owner or narrower delegated operator capability; exact approval for Critical actions | break-glass authority, project factual truth or task completion by administrative role alone |
| **WorkScope Owner** | scope resources, privacy/retention, local verifier/evaluation contracts and risk boundaries | approve/narrow WorkScope policy and applicable verifier contracts | authenticated WorkScope Owner role | global installation/Architecture policy or factual proof by designation alone |
| **Approver** | inspect exact Critical request/evidence/unknowns | one-shot approval or denial for the exact action hash | authenticated Approver role and current request | executing the action, changing its scope after approval, factual verification |
| **Recovery Principal** | break-glass/recovery view, exact repair/cutover surfaces | one bounded RecoveryLease transition | pre-established Recovery Principal role + incident/recovery evidence | normal project decisions, broad admin access, reusing break-glass as normal path |
| **Human observer / read-only** | ControlBoard, state, evidence, reports | observation/correction candidate only | authenticated local Human principal | any mutation or proof by assertion |

A single model process may perform several roles sequentially, but every role transition creates a new scoped capability context and updates the Independence Profile. It may not silently retain stronger authority from a previous role.

---

