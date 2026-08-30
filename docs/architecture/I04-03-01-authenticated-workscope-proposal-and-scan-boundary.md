### I4.3.1. Authenticated WorkScope proposal and scan boundary

An explicit path, project name or host hint is evidence, not scope authority. Resolution uses a `WorkScopeProposal` and produces a durable `WorkScopeResolutionReceipt`:

```yaml
WorkScopeProposal:
  proposer_principal_and_session:
  proposed_kind_and_resources:
  source: human | host | resumed_task | scanner | adapter
  authenticated_root_or_resource_identities:
  competing_candidate_refs:
  requested_privacy_and_authority_profile:

WorkScopeResolutionReceipt:
  selected_scope_and_generation:
  supporting_evidence:
  rejected_or_unresolved_candidates:
  owner_or_policy_authority:
  state_fence:
```

Unambiguous is not equivalent to authenticated. A scope whose principal/root/resource identity is not established remains provisional and cannot receive Material effects; dependent calls return `WORKSCOPE_UNAUTHENTICATED`.

BootstrapScanner applies privacy before durable capture:

```text
scan only registered/consented roots and fields;
collect the minimum ephemeral metadata required for discrimination;
command lines, editor state, recent output and neighboring roots are excluded by default;
secrets and high-risk literals are redacted or represented by non-reversible identity before persistence;
raw excluded material is not placed in logs, packets or model jobs;
ScanDisclosureReceipt records allowed, omitted, redacted and unresolved fields.
```

Missing privacy scope returns `SCAN_PRIVACY_BOUNDARY_REQUIRED`; the scanner may still offer a non-persisted discriminative question.

