## I15.17. Agent-generated Rust build threat model

Compiling untrusted or newly generated Rust executes native code through `build.rs`, proc macros, linker helpers, test binaries and downloaded tooling. WASM isolation of the eventual component does not sandbox its build.

Build trust classes:

```text
T0 known first-party change
  disposable worktree, dedicated target, no user secrets, Job Object limits;

T1 agent-generated change on admitted dependencies
  restricted testd identity/environment, allowlisted tools, network denied by default,
  write access limited to worktree/target/temp/artifact roots;

T2 new/untrusted dependency, build script, proc macro or foreign native code
  disposable VM/isolated laboratory route, or no local execution until approved.
```

Windows Job Objects control process lifetime and resources but do not isolate filesystem, registry, network, ports or user credentials. Therefore T1/T2 claims require a proven token/ACL/network boundary; if it is unavailable, ELIOT reports the missing guarantee and routes the build to a disposable VM/cloud lab instead of calling the process “sandboxed”.

Minimum build policy:

```text
exact toolchain/lockfile/source provenance;
no inherited broad environment;
no model/provider/DB credentials;
network denied unless dependency acquisition is a separate recorded phase;
dedicated target/cache namespace;
process tree and output limits;
artifact hashes and SBOM/license/advisory report;
cache identity includes trust class and source/lock/toolchain fingerprints;
release artifact attestation references build and test receipts.
```

A build cache is a trust boundary. Artifact reuse across trust classes or mismatched BuildFingerprint is forbidden.


