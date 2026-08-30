## I18.44. Build sandbox, supply-chain and cache tests

The build plane must prove the guarantees it claims:

```text
build script/proc-macro cannot read a seeded forbidden secret;
network deny or separately authorized acquisition is observable;
worktree/target/temp ACL boundaries hold;
Job Object cancellation removes descendant processes;
cache cannot cross trust/source/toolchain fingerprints;
malicious oversized output cannot deadlock the runner;
SBOM/license/advisory/provenance artifacts bind to release hashes;
VM/lab fallback is selected when local isolation is insufficient.
```

A Job Object-only test cannot claim filesystem/network sandboxing.

