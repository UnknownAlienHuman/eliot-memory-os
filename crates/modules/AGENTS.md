# Module execution source instructions

This subtree owns mechanics for immutable WASM/native Module generations. It
does not own Module admission intent, task semantics, authority/effects,
promotion, provider policy, canonical writes, or finish. Issues #21 and #22 own
the WASM and native contours; #13 binds cell/proof identity.

## Hard boundaries

- Every invocation binds exact artifact, config, protocol/facet/WIT identity,
  Module Catalog revision, capability envelope, State Fence and Authority Epoch.
- Capabilities/resources are explicitly introduced. Unintroduced filesystem,
  network, process, secret, device, clock/random or native resource access is
  absent, not merely checked after creating a broad ambient world.
- Host/worker adapters decode, validate, call and encode. They do not add retry,
  task meaning, policy, fallback, route selection, approval or finish semantics.
- WASM shadow execution is effect-free by construction. Canary effects require
  a separate exact permit and old-generation fencing.
- Native execution uses the shared governed process contract and exact
  execution manifest. No ambient environment/PATH/handles/user token or generic
  shell behavior.
- Trap, resource exhaustion, cancellation and cleanup affect only the exact
  Store/instance/process generation. No leaked handles/descendants or poisoned
  shared state.
- Caches/pools are rebuildable acceleration and never carry proof, authority,
  freshness or old-generation resources across restart/cutover.
- Contours claiming one facet pass the same ELIOT-owned differential/conformance
  corpus or report explicit divergence.

## Proof and stop condition

Changes require capability-denial and identity mismatch negatives, resource
limit/cancel/trap/cleanup proof, stale generation/epoch rejection and the real
WASM/native edge. Shadow/canary changes prove no-effect/permit/cutover/rollback.
Native credentials/resources additionally require non-disclosure and TOCTOU
substitution/revocation tests.

Stop when requested behavior belongs to Governor admission/promotion, Kernel
generation authority, User Broker credentials, task scheduling, canonical
storage, or provider/model policy.
