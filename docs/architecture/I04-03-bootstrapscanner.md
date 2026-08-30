## I4.3. BootstrapScanner

Scanner is a deterministic fast pass. It must complete without a model call.

It collects:

```text
canonical paths and filesystem identity;
Git presence, branch, commit, dirty summary;
file type distribution;
manifests and project units;
known build/test commands from registered profiles;
running processes/services connected to roots;
open editor/workspace metadata;
existing ELIOT project records;
available LSP/code graph/tool adapters;
recent filesystem changes;
known artifacts and output directories;
required execution identity for each root/tool and whether a matching User Broker is attached.
```

Output:

```yaml
ProvisionalScopeProfile:
  proposed_kind:
  identity_fingerprint:
  roots:
  project_units:
  likely_languages:
  active_resources:
  truth_surfaces_available:
  verifier_candidates:
  adapter_candidates:
  capability_gaps:
  confidence:
  onboarding_recommendation: none | shallow | normal | deep
  scan_evidence_refs:
```

