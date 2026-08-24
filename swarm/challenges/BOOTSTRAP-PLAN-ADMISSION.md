# ContractChallenge: bootstrap plan cannot honestly be admitted

- Work item: `W0-BOOTSTRAP-PLAN-ADMISSION`
- Contract revision: `recovery-w0-w1-r1-d40a0a1`
- Status: `CHALLENGED`
- Owner: Sol
- Normative references: `I17.2`, `I17.14`, `I17.15`

## Conflict

The recovery program requests `swarm/plan/<wave>/plan.json` as a signed
`AdmittedSwarmPlan`. Current source deliberately defines
`AdmittedSwarmPlan` as `Serialize` only, with private fields, and documents that
it cannot be deserialized or publicly constructed. Admission requires a
provider binding and a verified `ReceiptEnvelope`.

Exact current anchors:

- `crates/agent/eliot-swarm/src/lib.rs:624-645` — inert
  `SwarmPlanProposal` versus non-deserializable `AdmittedSwarmPlan`.
- `crates/agent/eliot-swarm/src/lib.rs:789-887` — admission request, receipt
  validation, and construction.
- `crates/agent/eliot-swarm/src/repair_tests.rs:356-386` — test-only admitted
  fixture; not a production authority path.

Writing a hand-authored admitted JSON document would fabricate the exact
authority boundary the recovery program is meant to restore.

## Sol decision

Use a content-addressed, inert `SwarmPlanProposal` as `BootstrapDraft` and keep
the gate open. Do not emit `plan.json` under an admitted name until a real
provider issues a receipt that `eliot-swarm::admit_plan` verifies. External
audit sessions and local mutation lanes may proceed as bounded evidence, but
they do not promote the proposal.

## Resolution condition

The challenge closes only when a native command can:

1. validate the proposal graph;
2. bind current source and normative revisions;
3. obtain a provider-issued admission receipt;
4. call the production admission path; and
5. serialize the resulting `AdmittedSwarmPlan` without caller-fabricated
   authority.
