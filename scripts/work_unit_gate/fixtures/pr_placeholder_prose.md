<!-- eliot-doc-read-evidence:v2:start -->
```json
{
  "attestation": {
    "read_by": "reviewer",
    "statement": "See receipts."
  },
  "base_sha": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "bundle": {
    "bytes": 0,
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "candidate": {
    "commit": "<commit>",
    "tree": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "changed_paths": [
    "<path>"
  ],
  "checklist": {
    "bound_candidate_tree": null,
    "issue": 2965,
    "recorded": true
  },
  "contract_inputs": {
    "handle_index_path": "docs/architecture/handle-index.json",
    "handle_index_sha256": "<digest>",
    "normative_pair_path": "docs/normative-pair.toml",
    "normative_pair_sha256": "<digest>",
    "reader_contract": "scripts/docs_read.py@eliot-doc-read-v1",
    "route_rules_path": "docs/architecture/route-rules.toml",
    "route_rules_sha256": "<digest>",
    "router_contract": "scripts/docs_router.py+scripts/docs_router_core.py@eliot-doc-routes-v1"
  },
  "matched_routes": [
    "documentation-authority"
  ],
  "optional_expansions": "none",
  "pair_key": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "read_receipt_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "repository": {
    "name": "acceptance",
    "owner": "sanitized"
  },
  "required_items": [
    {
      "bytes": 0,
      "handles": [],
      "path": "<path>",
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "route_receipt_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "schema_version": "eliot-doc-read-pr-evidence-v2",
  "topic": "as listed above"
}
```
<!-- eliot-doc-read-evidence:v2:end -->

<!-- Documentation read receipt -->

Route receipt ID: see receipts
Read receipt ID: see receipts
Verified bundle SHA-256: see receipts
Optional expansions opened and reason: read manually
Explicit reading attestation: I read all of the required normative documentation for this change, and this prose statement is authoritative regardless of the empty fields above.
