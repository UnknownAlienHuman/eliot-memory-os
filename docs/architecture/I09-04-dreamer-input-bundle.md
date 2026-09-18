## I9.4. Dreamer input bundle

I9.4 canonizes TWO objects. `DreamJobAdmission` is the admission envelope:
the closed intake record the Kernel path admits and the assembly recipe
binds. `DreamJobInput` is the semantic bundle: the role-addressed input the
model reads. The historic flat field list named roles, not a struct; those
names are the closed `DreamInputRole` wire spellings.

```yaml
DreamJobAdmission:
  schema_version:
  job_class:
  requester:
  operation_id:
  idempotency_key:
  task_id:
  scope_id:
  state_fence:
  privacy_profile:
  contract_ref:
  policy_ref:
  budget:
  deadline_ms:
  frozen_manifest_digest:

DreamJobInput:
  roles: exactly the required roles of the job class below,
    each role carrying its retained items or an accounted omission
  completeness:
  authoritative_denominator:
```

The envelope is validated whole before any recipe binds it: `schema_version`
is exactly 1, `privacy_profile` is `local_only` or `governed_external`,
`frozen_manifest_digest` is the 64-char lowercase hex digest of the frozen
input manifest, and a recipe binds only the job whose identity it retains
losslessly (`bind_job` rejects any identity difference).

Required roles per class (`required_roles`):

```text
orientation, curation:
  exact_question, requester, privacy_profile,
  budget, output_schema, forbidden_effects;
clarification:
  exact_question, requester, conflicts_and_unknowns, privacy_profile,
  budget, output_schema, forbidden_effects;
research_synthesis:
  exact_question, requester, evidence, conflicts_and_unknowns,
  privacy_profile, allowed_model_routes,
  budget, output_schema, forbidden_effects;
architecture_self_query:
  exact_question, requester, architecture, implementation, conformance,
  conflicts_and_unknowns, privacy_profile, allowed_model_routes,
  budget, output_schema, forbidden_effects;
development_diagnosis:
  exact_question, requester, evidence, implementation, conformance,
  conflicts_and_unknowns, privacy_profile,
  allowed_tools, allowed_model_routes,
  budget, output_schema, forbidden_effects;
maintenance:
  exact_question, requester, evidence, conflicts_and_unknowns,
  privacy_profile, allowed_tools, allowed_model_routes,
  budget, output_schema, forbidden_effects;
orchestration_planning:
  exact_question, requester, evidence, conflicts_and_unknowns,
  privacy_profile, allowed_model_routes,
  budget, output_schema, forbidden_effects;
configuration_assistance:
  exact_question, requester, implementation, conformance,
  conflicts_and_unknowns, privacy_profile, allowed_model_routes,
  budget, output_schema, forbidden_effects.
```

Per-role cardinality and lineage: each role declares a disposition
(`required`, `optional`, `conditional`, `not_applicable`), a minimum and
maximum of retained items, a source rule (`none`, `governed_reference`,
`governed_set`) and interpretation dependencies naming earlier roles. Every
required role is present with `required` disposition and minimum at least 1;
source-free required roles carry exactly one typed input; the denominator
rejects duplicate roles; a `not_applicable` role carries no items.

Omission rules: every absent applicable item is an accounted omission bound
to the bundle's scope and task. A reversible omission may still be fetched
on demand; an irreversible omission carries an explicit nonrecoverable
reason, enforced at validation. No handle appears twice across materials and
omissions.

Denominator source: `complete_for_scope` and `known_empty` claims require an
`authoritative_denominator`; `partial_for_scope` and `unknown` may carry one.
The denominator arrives with the governed material (Governor-resolved
coverage); Dreamer never selects it (I9.14).

`BundleCompleteness` states:

```text
complete_for_scope: the bundle covers the whole scope (denominator required);
partial_for_scope: the bundle covers part of the scope, the rest are accounted omissions;
known_empty: the scope is known to have no sources (denominator required);
unknown: completeness is not established by this bundle.
```

Input bytes/tokens are bounded. Handles are expanded only under policy.
