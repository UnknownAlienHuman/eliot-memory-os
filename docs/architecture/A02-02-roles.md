## A2.2. Roles

A role description defines function, not implicit permission. Every state change or effect requires applicable authority. Authority may be delegated in advance to a role, work item, policy, or lease and checked automatically; separate ceremony is needed only at a boundary of impact, uncertainty, or delegation. Anything outside granted authority is prohibited. General degradation of roles and services is governed by A13.11, not hidden exceptions here.

### Human Roles

- **Requester / Domain Owner** sets the goal, values, constraints, and acceptance criteria.
- **Architecture Owner** approves Architecture changes.
- **System Owner** manages installation, credentials, model routes, and system delegation.
- **WorkScope Owner** defines local policies, protected resources, and accepted verifiers.
- **Approver** authorizes an exact Critical action.
- **Recovery Principal** performs a narrow break-glass transition.

One person may hold several roles, but their authority does not merge automatically.

### Main Agent

Interprets meaning, develops competing models, selects inquiry or action, and proposes decisions. It creates no independent verification authority, policy, or factual proof.

### Task Controller

Owns the current plan revision and coordination of one task under the active Authority Epoch. The Main Agent usually carries this responsibility; a Human may assume it explicitly. The Task Controller does not own factual truth, Architecture, or system-wide policy.

### Governor and Kernel

The Governor is the sole application owner of canonical transitions, authority, task state, context compilation, and receipts. The Kernel is its minimal resilient core, not a second Governor.

### Canonical Memory

Preserves cognitive inheritance and history. It is neither an agent, truth source, nor policy owner.

### Truth Surfaces and Verifiers

A truth surface provides an observation about a specific property. A Verifier checks an expected property in a known scope. Neither defines the goal nor proves more than its Evaluation Contract.

### Harness and Agent Coordinator

The Harness connects the model, host, tools, and Governor. The Agent Coordinator manages the durable work graph, sessions, budgets, leases, and aggregation. Neither makes the substantive decision.

### Host Supervisor

Operates outside the shared process failure domain of the main services. It performs only start, stop, bounded restart, and approved rollback; it neither reads project semantics, forms a diagnosis, nor grants canonical authority.

### Watchdog and Doctor

The Watchdog independently observes liveness, protocol discipline, security, and integrity. The Doctor diagnoses Modules and performs only registered, bounded repairs.

### Dreamer

Runs bounded AI jobs for curation, orientation, research, and clarification. It owns no memory, policy, truth, or final decision.

### Workers, Auditors, Verifier Agents, Synthesis Agents, and Curators

Perform narrow work and return candidate artifacts and evidence. Their role does not elevate result authority.

### Human Control Plane

Displays canonical state and lets a person issue decisions, approvals, Dreamer or Watchdog questions, and recovery actions. It is not a second owner.

