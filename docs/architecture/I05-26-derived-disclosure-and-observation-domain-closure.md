## I5.26. Derived disclosure and observation-domain closure

Governor owns canonical observation-domain lineage, disclosure closure revisions and DisclosureDecisions. Source/adapter ingress may attach direct domain observations; Context Compiler and Agent Coordinator compile closures for exact packets/waves; Watchdog observes bypass or leakage; Dreamer may only propose a transformation or classification candidate.

Epistemic provenance and disclosure permission are separate graphs.

```text
Influence Dependency Closure
  answers what currently supports or influences a representation;

Disclosure Dependency Closure
  answers which authorization/privacy domains remain material to it
  and therefore constrain where it may be sent or shown.
```

A public false claim can be freely disclosed and have zero support. A verified private fact can have strong support and narrow disclosure. Summary, compaction, Dreamer synthesis, model restatement or adapter normalization does not clear either lineage.

### Observation domains

`ObservationDomainRef` labels policy-sized source domains, not every token or line:

```yaml
ObservationDomainRef:
  domain_id:                    # opaque, non-revealing stable ID
  protected_display_label_ref:  # optional; never required on hot path
  kind: local_root | connected_resource | user_private | tenant |
        secret_class | provider_retention | licensed_source | custom
  authority_root:
  resource_scope:
  privacy_class:
  visibility_and_export_rule:
  model_route_rule:
  ACL_or_verifier_adapter:
  generation_and_state_fence:
```

Logical examples (not literal wire IDs):

```text
private repository domain;
connected-drive folder domain;
production credential class;
human-private domain;
provider-retention class;
non-redistributable corpus.
```

Stored domain IDs are opaque. Human-readable labels are protected metadata and may be purged or redacted while a non-revealing tombstone/digest preserves revocation and audit continuity. Closure membership is security metadata; it is not automatically exposed to the recipient whose disclosure is being decided.

### Closure and decision

```yaml
DisclosureDependencyClosure:
  closure_id:
  subject_ref:
  direct_domain_refs:
  inherited_closure_refs:
  derivation_or_transformation_refs:
  completeness: complete | partial | unknown
  declassification_receipt_refs:
  policy_snapshot_id:
  state_fence:
  revision:

DisclosureDecision:
  subject_and_closure_ref:
  recipient_principal_or_route:
  recipient_capability_set:
  covered_domains:
  uncovered_domains:
  decision: allow | allow_redacted | recompute_narrower |
            fork_private | require_authority | deny
  policy_snapshot_and_state_fence:
  receipt_ref:
```

A model-written claim that sensitive material was removed is not declassification. Subtracting a domain requires a registered deterministic or externally verified transformation:

```yaml
DeclassificationReceipt:
  input_closure_ref:
  transformation_id_and_version:
  exact_input_and_output_hashes:
  removed_or_generalized_domains:
  preserved_domains:
  verifier_and_property:
  residual_limitations:
  authority_and_policy_ref:
```

### Propagation

```text
capture
→ attach direct ObservationDomainRefs;

deterministic/model transformation
→ union all input closures by default;

registered sanitizer/aggregator
→ may remove a domain only through DeclassificationReceipt;

packet/model/swarm compilation
→ compute exact output closure;

route/share/export admission
→ compare closure with principal/route capabilities;

privacy/ACL/source change
→ invalidate dependent DisclosureDecisions by explicit edges.
```

Authorization, WorkScope and disclosure closure are enforced before candidate generation and again after every selection-transforming stage: graph pivot, rerank, community/cluster expansion, summary, context compilation, tool invocation and export. An unauthorized structural edge or shared-history signal cannot change candidate membership merely because the final facts are individually authorized. ELIOT reports unauthorized retrieval, selection-integrity harm and benign cross-user/route behavioral contamination as distinct outcomes; final packet filtering is not a cure for an already contaminated decision path.

For a shared `RootContextRevision`, adding evidence with a broader closure creates a new revision and reruns admission for every recipient. If one recipient lacks coverage, ELIOT chooses one explicit result:

```text
private fork;
verified redacted projection;
recipient re-authorization/removal;
narrower task;
denial.
```

It never silently upgrades a shared root.

Failure behavior:

```text
complete closure + covered recipient
  → normal delivery;

partial/unknown closure
  → local processing may continue inside the current boundary;
  → remote/export/share returns `DISCLOSURE_CLOSURE_INCOMPLETE`
    or is recomputed narrower;

ACL adapter unavailable
  → no access is inferred from login or prior success;

sanitizer inconclusive
  → full input closure remains;

revocation after delivery
  → stop future delivery, revoke enforceable handles,
    retain delivery receipt and open a Problem when external recall is impossible.
```

The closure uses stable domain IDs and compact sets/bitsets on hot paths; full evidence remains handle-based. ELIOT does not build a global per-datum observer graph.


