## I15.18. Disclosure, delegation and facet security

Security admission evaluates four independent questions:

```text
is the content/observation epistemically admissible;
is it allowed to influence this decision/action;
is the holder authorized to call the operation;
is the derived result allowed to be disclosed to this recipient/route.
```

No earlier `allow` implies a later one.

### Disclosure gate

Before a packet, model bundle, report, swarm root, artifact or result crosses a principal/route boundary:

```text
resolve Disclosure Dependency Closure;
require complete closure or explicitly local-only/unknown behavior;
match every material domain to recipient/route capability;
apply verified declassification only by receipt;
record DisclosureDecision;
bind the decision to exact State Fence and route/provider retention profile.
```

A missing/inconclusive ACL or sanitizer fails closed for external disclosure while preserving local work where possible.

### Delegation gate

Before use:

```text
validate active CapabilityGrant path;
validate graph revision, epoch, expiry and use budget;
validate exact CapabilityIntroduction and FacetManifest method;
validate credential owner/acting principal;
validate operation/effect/data/disclosure classes.
```

Revocation invalidates new calls before semantic reconciliation, interrupts enforceable live handles and preserves forensic history. An old serialized introduction is not authority after restart/restore.

### Facet attack surface

Tool/resource method definitions are cognitive and security inputs. Method classification is default-deny; unclassified methods are not exported. Facets expose the minimum exact operations and handles needed for one WorkItem/Attempt. Generic raw shell, DB, filesystem, connector catalogs or all-account access are not introduced by default.

Required release/load-bearing tests include:

```text
derived A+B result sent to A-only recipient;
model summary retaining hidden private closure;
verified sanitizer and failed sanitizer;
shared-wave future evidence broadening;
grant diamond and last-path revocation;
cycle insertion;
revocation of active agent/WASM/native handle;
old handle after restore;
unintroduced globally installed resource;
unclassified new public method;
credential inheritance attempt;
same facet conformance across WASM/native/agent proxy.
```

These mechanisms must remain bounded:

```text
policy-sized domains, not per-token labels;
acyclic grant lineage, not arbitrary permission fixed points;
stable facet families + dynamic handles, not per-task schema explosion;
local work not blocked by future multi-user/distributed features.
```


