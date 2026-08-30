## I21.7. Reference firewall and unsupported precision

Every Dreamer, Researcher, audit, local-model and external-model job receives an `AllowedReferenceManifest` bound to the exact run and State Fence:

```yaml
AllowedReferenceManifest:
  run_job_and_root_context_revision:
  allowed_source_record_evidence_artifact_and_url_handles:
  allowed_tool_definition_and_verifier_refs:
  allowed_anchor_or_coordinate_precision:
  scope_disclosure_and_retention_classes:
  stale_or_revoked_entries:
  expansion_routes:
  manifest_digest_and_state_fence:
```

A model may quote, summarize or select only entries in this manifest. It cannot mint a valid citation, URL, source ID, line range, artifact handle or support relation through prose. A syntactically plausible but absent/stale/wrong-scope reference remains unsupported text and produces a candidate diagnostic rather than an evidence edge.

A newly mentioned external URL or identifier may be captured as an untrusted `ObservationCandidate` for later acquisition, but it is not treated as an allowed source or citation for the current run until an admitted provider resolves and snapshots it, Researcher records its source-admissibility disposition, and Governor applies the resulting `SourceRecord` transition through the sole canonical writer.

```yaml
UnsupportedPrecisionItem:
  asserted_reference_or_coordinate:
  highest_supported_precision:
  source_and_coverage_basis:
  risk_of_false_precision:
  required_probe_or_narrower_wording:
```

A source that supports a file-level or document-level claim does not automatically support a symbol, line, causal mechanism or population-wide statement. Reference validation occurs before candidate promotion and again when a result is packed into a shared packet or exported to another route.

The firewall does not censor model reasoning. It separates free-form hypotheses from support that ELIOT is allowed to represent as anchored evidence.

