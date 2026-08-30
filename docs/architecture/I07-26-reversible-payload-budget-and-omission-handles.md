## I7.26. Reversible payload budget and omission handles

Every material payload is either delivered completely or shortened through a durable reversible projection. Silent truncation is forbidden.

```yaml
OmittedPayloadRef:
  omission_id:
  source_blob_or_operation_ref:
  source_checksum:
  original_bytes:
  rendered_bytes:
  omitted_count_or_ranges:
  omission_reason:
  preserved_priority_classes:
  renderer_and_budget_profile:
  created_at:
  retention_and_expiry:
  expansion_uri:
  completeness: complete_source_preserved | partial_source |
                source_unavailable | unknown
```

Algorithm:

```text
1. Normalize/redact according to privacy policy.
2. Persist the admissible exact source or existing BlobRef before rendering a
   material shortened view.
3. Apply a typed reducer or deterministic range selection.
4. Preserve errors, failure signatures, exit status and exact anchors first.
5. Preserve exact quoted spans that carry evidential weight before any generative restatement.
6. Return preview + omission handle + completeness metadata.
7. Expansion reads the stored source; it never re-executes the original tool/effect.
8. Expired/missing source yields `OMITTED_SOURCE_UNAVAILABLE` with an explicit unavailable/partial result; the original effect is never re-executed.
```

If a material omitted portion cannot be durably preserved, the response cannot claim completeness or satisfy proof. It returns an evidence-incomplete/truncated disposition with a Recovery Directive. For non-material convenience views, an explicit partial preview is allowed but never promoted.

`OutputReducer` families are replaceable renderers for tests, build, lint, Git, search, logs and file listings. They preserve exit code and raw handle and do not decide semantic truth. A reducer that does not reduce size passes through the source unchanged.

Payload budgets apply consistently to:

```text
MCP/EBP responses;
tool/instrument output;
CodeCortex and Dreamer packets;
diffs and reports;
swarm reduction artifacts.
```

The Blob Store is the only payload substrate. RepoWise-style omission is not implemented as another semantic SQLite store.


