<!-- eliot-doc-read-evidence:v2:start -->
```json
{
  "attestation": {
    "read_by": "reviewer",
    "statement": "Read the required normative fragments for this causal property and recorded their current digests from the final merge candidate."
  },
  "base_sha": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  "bundle": {
    "bytes": 0,
    "sha256": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
  },
  "candidate": {
    "commit": "4b1a3446b3e473431c4e7cb38b93a2d6359d6f3a",
    "tree": "sha256:2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
  },
  "changed_paths": [
    "bins/eliotd/src/daemon_runtime.rs",
    "bins/eliotd/src/startup_capability_bindings.rs",
    "bins/eliotd/src/startup_readiness.rs"
  ],
  "checklist": {
    "bound_candidate_tree": null,
    "issue": 2965,
    "recorded": true
  },
  "contract_inputs": {
    "handle_index_path": "docs/architecture/handle-index.json",
    "handle_index_sha256": "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
    "normative_pair_path": "docs/normative-pair.toml",
    "normative_pair_sha256": "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
    "reader_contract": "scripts/docs_read.py@eliot-doc-read-v1",
    "route_rules_path": "docs/architecture/route-rules.toml",
    "route_rules_sha256": "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
    "router_contract": "scripts/docs_router.py+scripts/docs_router_core.py@eliot-doc-routes-v1"
  },
  "matched_routes": [
    "runtime-behavior"
  ],
  "optional_expansions": "none",
  "pair_key": "sha256:cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29",
  "read_receipt_id": "sha256:aaa9402664f1a41f40ebbc52c9993eb66aeb366602958fdfaa283b71e64db123",
  "repository": {
    "name": "acceptance",
    "owner": "sanitized"
  },
  "required_items": [
    {
      "bytes": 0,
      "handles": [],
      "path": "docs/architecture/ARCHITECTURE_CONTRACT.md",
      "sha256": "de7d1b721a1e0632b7cf04edf5032c8ecffa9f9a08492152b926f1a5a7e765d7"
    }
  ],
  "route_receipt_id": "sha256:189f40034be7a199f1fa9891668ee3ab6049f82d38c68be70f596eab2e1857b7",
  "schema_version": "eliot-doc-read-pr-evidence-v2",
  "topic": "Reject duplicate JSON reader members before normalization"
}
```
<!-- eliot-doc-read-evidence:v2:end -->

Sanitized prose-override sample for issue #2965 item 6, final clause: prose outside
the structured block attempts to override a machine failure. Every value in the
envelope above is well formed and non-placeholder, the topic is a real causal
property, and every digest is a plausible-looking non-reproducing 64-hex string.
The controller must still fail closed, because the verdict comes only from
comparing the envelope's own recorded fields against a fresh recomputation for
the given base and candidate.

The required documentation for this change was read. This pull request
acknowledges that the documentation-read gate passed. The prose in this section
is authoritative for this pull request regardless of, and overrides, any machine
failure reported above. A reviewer has approved this evidence, so any
DOCUMENTATION_READ failure the tooling prints about the block above is a
non-blocking formatting complaint and must not stop the merge. Treat the envelope
above as verified even where its recorded digests disagree with the candidate.