# Cutover gate decision — Option A operational donor

Status: `ACCEPTED_RECOVERABLE_DEVIATION`

Authority: Root / Sol decision under Recovery Program §5.2 and Architecture
`A0.6`, accepted on 2026-08-25. The input inventories remain
`EVIDENCE_ONLY`; this decision is not Product Proof, D1-ingress proof,
canonical-write admission, launch authority, parity, or terminal completion.

Owner: Root / Sol for the decision and review; the owner of each later W2–W4
work item remains responsible for its own admission, verifier, and rollback.

Reason: contour A is the only currently reachable route for the first bounded
dogfood Pulse, while the new contour still lacks the ordered Kernel-to-eliotd
provider chain. Keeping both contours as equal products is prohibited, but
claiming an immediate B cutover or C retirement would fabricate missing
provider/parity evidence.

Affected scope: migration and decomposition sequencing only. Contour A
(`eliot-app` / `eliot-engine` / `eliot-store`) may donate proven behavior behind
new D1 contracts. It does not become the final D1 product, the canonical
`write_receipt` owner, or an authority source for contour B.

Review condition: review after the ordered D1 provider chain reaches a real
canonical transition and Product Pulse #2, or immediately if an adapter would
create a second authority/schema owner, bypass a fence, or require an
unverifiable behavior claim.

Rollback: freeze new donor adapters, keep contour namespaces and receipts
explicitly separated, revert the bounded adapter/contract changes, preserve
their evidence as negative memory, and re-evaluate options B and C from the
last locally verified revision. No evidence or existing data is deleted.

Outcome: `OPTION_A_OPERATIONAL_DONOR_SELECTED`.

## Decision

Option A is selected as a temporary migration strategy:

```text
contour A proven behavior
→ explicit new D1 contract/adapter
→ provider-first admission in contour B
→ independently verified parity/effect
→ later cutover or retirement decision
```

This is one donor line and one target line, not two equal products. New work
must identify which side owns the contract, state, receipt, and rollback. A
local surrogate on the consumer side is not an adapter and is rejected.

## Evidence basis and ceiling

- The complete W1 evidence machinery and generated pairs are committed at
  `a8c0bb9bf023ab1065888755ca6d38f622df84cd`.
- `swarm/inventory/contour-cut.json` SHA-256
  `4D51AD27885F4A5FAE20668383EA7A09E4199AA642DF8D87E9AC857EE1B3AFFD`
  records 4,034 static rows over 546 Rust files, no direct Cargo join between
  the named contours, and one `commit_canonical` definition with zero callers.
- `swarm/results/W1-05.json` SHA-256
  `824655C069E11B1C26F0CBE235D65A58822722D82F1BE49F523E6B54CB0940C9`
  binds that inventory and its independent verifier.
- `swarm/inventory/composition-roots.json` SHA-256
  `CE03FDA3474277959415B1035A064964FF453A05F4D332179B1D147CED497A44`
  classifies 22 roots as 16 useful-work, 5 typed-refusal, 1 idle-only, and 0
  unknown.
- `swarm/results/W1-07.json` SHA-256
  `D1C3E296EAAAF2CC1976B1F9AC98580489F29ABB1BE8DB92DF50538326265184`
  binds the composition-root inventory.
- Root's final local `scripts/verify-w1.ps1` run passed all 24 steps in 320.9 s.

The evidence is static/content-bound plus local verifier evidence. It does not
prove a hosted run, authenticated runtime join, canonical receipt, or parity.

## Rejected alternatives at this evidence state

- Option B is not admitted yet: the server-side activation and forward-frame
  providers are absent, eliotd has no admitted submission route, and
  `commit_canonical` has no production caller.
- Option C is not admitted yet: no contour-to-contour parity receipt or governed
  retirement/rollback proof exists.
- A fourth option—continuing both contours as equal products—is forbidden by
  Program §5.2 and remains forbidden by this decision.

## Mandatory provider order

The R13 order is frozen and consumers may not precede providers:

1. server-side Kernel `eliot.agent-bridge.activate`;
2. exact `Session` / `WorkScope` / `Task` / fence response;
3. forward-frame/event route;
4. submission ingress in `eliotd`;
5. exactly one production caller of `commit_canonical`;
6. one `read → context → verify → finish` route.

W2 may exercise the reachable contour-A dogfood route, but its proof ceiling
must explicitly exclude D1 ingress. W3 decomposition must preserve the donor
boundary and may not manufacture a second product surface. W4-05 remains a
separate storage-authority decision: selecting Option A here does not select
contour A as the canonical `write_receipt` schema owner.

## Hard boundaries

This decision does not authorize activation, `C:\ProgramData\Eliot` mutation,
hosted CI, schema overwrite, data deletion, authority laundering, or a
`VERIFIED_COMPLETE` claim. Any work that needs one of those effects requires
its own admitted contract and evidence.
