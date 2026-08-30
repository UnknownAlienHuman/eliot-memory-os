## I21.11. Research federation provider

`ELIOT Research` is a separate external cognitive/research system with its own database, acquisition/indexing stack, tools, agents and lifecycle. It is not the Researcher plane or a privileged in-process owner and never shares ELIOT’s canonical database or authority lineage.

The Research endpoint, bridge, protocol and exchange classes are admitted through the normal `RuntimeInstallation`/`HostAdapterManifest`/`CapabilityEvidenceRecord` path. Endpoint reachability or a successful login proves neither source coverage nor permission to disclose a bundle. Each exchange binds the exact Research system/bridge generation, dynamic capability pulse, principal, disclosure policy and retention contract; stale or unqualified evidence blocks only the dependent exchange.

The bridge exposes an ELIOT-owned `ResearchExchangeContract` through a replaceable module/process adapter:

```yaml
ResearchQueryRequest:
  exchange_id_protocol_bridge_and_idempotency:
  requester_principal_authority_and_state_fence:
  question_scope_and_expected_decision:
  source_classes_and_coverage_goal:
  ELIOT evidence/report handles allowed for export:
  privacy_disclosure_retention_and_license:
  budget_deadline_stop_and_progress_contract:
  required result schema_and_citations:

ResearchEvidenceBundle:
  exchange_request_job_system_and_version:
  immutable_bundle_digest_and_origin_authentication:
  source_catalog_snapshots_and_exact_citations:
  claim_counterclaim_and_independence_matrix:
  bounded excerpts_and_artifact_handles:
  coverage_unknowns_and_failed_acquisition:
  synthesis_as_candidate:
  disclosure_and_invalidation:

ResearchExportBundle:
  exchange_id_protocol_and_ELIOT_product_identity:
  large ELIOT report_trace_or_service dossier:
  exact artifact/source handles and redactions:
  purpose_allowed_use_retention_and_return_channel:
  disclosure_decision_and_export_receipt:
```

Dreamer may query Research when local cognitive inheritance lacks external knowledge, and may submit an important large report or service dossier for deeper processing. Returned material enters ELIOT as governed sources, evidence candidates and bounded briefs; it does not become Current Epistemic Position or a procedure automatically. Persistent large documents, corpora, embeddings and document-processing intermediates belong in Research. Main ELIOT BlobStore may retain only bounded operational artifacts/log segments under explicit retention or transfer policy; it is not a long-term research corpus. Main Cognitive Inheritance stores source cards, exact handles, bounded excerpts, decisions, outcomes and the compact knowledge needed for hot work.

A deterministic `CorpusPlacementDecision` prevents accidental corpus growth:

```text
cognitive_hot
  source card, bounded excerpt, claim/decision/failure/procedure needed for current work;

operational_evidence
  immutable artifact/log segment retained for exact proof, replay or transfer;

research_corpus
  source set requiring persistent bulk storage, OCR/parsing, repeated full-text/vector/RAG,
  document-level synthesis or long-horizon research maintenance.
```

The decision is based on purpose, access pattern, processing lifecycle, retention/privacy and expected cognitive use—not one universal byte threshold. A payload placed in Research remains reachable by governed handle and can later yield a compact ELIOT candidate; it is not silently copied back in full.

The federation is asynchronous and durable: jobs expose progress, cancellation, partial results, source coverage and terminal disposition. Research may internally use its own agents/swarms, but ELIOT controls only the admitted external job boundary unless the protocol exposes verifiable descendant lineage. Unobserved internal agents receive no independence credit and cannot create ELIOT authority or proof. Research failure degrades external knowledge only. Direct remote DB access, shared credentials, implicit bidirectional replication and Research-initiated ELIOT writes are forbidden.

When a current task depends on a Research-held source, ELIOT may use only a still-valid bounded excerpt/evidence bundle already admitted under its State Fence. It does not invent the missing content or silently fall back to a stale summary. If the required bundle cannot be fetched or its disclosure/source generation cannot be verified, the dependent inquiry returns `RESEARCH_SOURCE_UNAVAILABLE` or `INCOMPLETE_COVERAGE`, while unrelated local cognitive work continues. Pending exports/imports remain durable exchange jobs and resume by idempotency identity rather than duplicate transfer.

