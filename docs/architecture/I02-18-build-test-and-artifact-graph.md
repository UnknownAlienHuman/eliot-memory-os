## I2.18. Build, test and artifact graph

`BuildTestGraph` is the agent-planning/affected-proof projection over the narrower `BuildExecutionGraph`, `VerifierCoverageGraph`, public contracts, runtime bundles and failure history. It is not a third graph owner and never invents build/test edges not present in those sources.

`BuildTestGraph` is compiled from:

```text
Cargo metadata package/target/feature graph;
source-to-crate ownership;
public contract digests;
Rust semantic edges where available;
test inventory and overlays;
process/runtime bundles;
Module/Instrument manifests;
historical failures and escaped regressions.
```

### Core identities

```text
CrateIdentity
  package id + source revision;

PublicContractDigest
  public Rust/schema/protocol surface;

BuildFingerprint
  toolchain + target + profile + features + env class
  + crate/source closure + build scripts + proc macros;

ModuleTestCapsuleRevision
  selector + fixtures + oracle + resource classes;

RuntimeBundleIdentity
  exact crates/artifacts/protocol manifest.
```

### Change selection

```text
private implementation change
  primary crate tests + known behavioral edges;

public contract change
  primary crate + direct/reverse consumers + contract tests;

proc-macro/build-script/generated-schema change
  all affected expansion/build consumers;

feature/workspace/toolchain/lock/profile change
  wider dependency closure;

process/protocol/state migration change
  affected runtime bundle, recovery edge and Product Pulse.
```

Cargo decides which compiler units to rebuild; ELIOT decides which proofs are required. These decisions remain distinct.

### Single-flight builds

One exact BuildFingerprint has one producer. Other lanes become waiters and receive the same artifact and evidence. A failed producer is not restarted by every agent without a new hypothesis or identity.

