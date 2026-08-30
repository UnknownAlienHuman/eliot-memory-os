## I16.15. Architecture, Implementation and donor coverage reports

`ArchitectureConformanceReport` compares Architecture anchors with accepted Implementation sections and observed owner/mechanism/failure/proof/status.

`ImplementationConformanceReport` compares the accepted Implementation revision with:

```text
current crate/process/module ownership;
wire/schema/config and migration versions;
active DEFAULTs and Research Gates;
code/tests/runtime receipts;
known deviations and unsupported contracts;
source and artifact digests.
```

A report never treats running behavior as an automatic correction of the book. It classifies the mismatch and names the decision owner.

`DonorCoverageManifest` is the machine-readable source for retirement evidence:

```yaml
DonorCoverageManifest:
  manifest_version:
  Architecture_and_Implementation_digests:
  donor_source_digests:
  heading_and_unique_mechanism_inventory:
  disposition_and_active_target_per_item:
  Architecture_conformance_rows:
  unresolved_document_semantics:
  repository_reference_scan_status:
  runtime_data_migration_status:
  archive_bundle_status:
  gate_verdicts:
```

`DonorMigrationReport` renders that manifest and reports:

```text
unmapped headings/mechanisms;
UNKNOWN dispositions;
retained contracts without active target;
stale donor references in code/tasks/config/live state;
independent document, Architecture, repository, runtime and archive gate status.
```

These reports prevent deletion of useful old material without making old books normative forever. They may not infer repository/runtime readiness from document coverage.

`OwnerRequirementTraceReport` preserves the user's normalized requirements without turning chat history into a third normative book:

```yaml
OwnerRequirementTraceReport:
  requirement_source_digest_and_item_id:
  preserved_intent_and_failure_mode:
  current_Architecture_ids:
  current_Architecture_intent_or_anchor:
  current_Implementation_owner_and_sections:
  disposition: preserved | clarified | superseded | challenged | unresolved
  document_support: present | partial | absent
  support_claim_and_snapshot_ref:
  support_observation_state: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
  contract_maturity:
  implementation_support:
  evidence_execution_status:
  failure_or_regression_evidence:
  next_discriminative_artifact:
```

Keyword presence, heading counts and a broad section link do not close a requirement. A trace row must explain the retained intent, current owner, any intentional narrowing and the observable proof. Its maturity, support and evidence fields use the exact I0.5 enums and must equal the bound support claim; `support_observation_state` alone carries observation availability/state and never contains or creates conformance support. The report becomes stale when the source requirement ledger, Architecture, Implementation or bound evidence snapshot digest changes.

