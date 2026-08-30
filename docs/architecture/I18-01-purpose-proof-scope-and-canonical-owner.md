## I18.1. Purpose, proof scope and canonical owner

Testing exists to distinguish competing explanations of system behavior and to provide grounded evidence to agents. It is not a separate product, a line-count target or a substitute for Architecture.

Every check declares:

```text
property and competing failure it distinguishes;
Product/WorkScope/base/candidate/tool identities;
real execution path;
coverage and freshness;
what PASS proves;
what PASS explicitly does not prove;
normal trigger, owner and retirement condition.
```

Proof levels never promote automatically:

```text
ShapeProof       — syntax/schema/literal/generated shape;
ModuleProof      — one micro-module behind its public contract;
EdgeProof        — provider/consumer or process/protocol edge;
IntegrationProof — affected real owners compose in one environment;
ProductProof     — end-to-end user property on accepted runtime;
ReleaseProof     — supported matrix, recovery, migration and packaging.
```

Canonical execution ownership:

```text
Instrument Registry owns profile definitions;
InstrumentRunner owns deterministic stage execution/aggregation;
ProcessExecutor owns external process semantics;
parsers own normalization only;
Governor owns evidence admission and verifier binding;
FinishService owns task completion;
Justfile/CI/agent surfaces are thin callers of the same profile.
```

A test report, status file or tool exit code is not evidence until it is bound to exact identity, coverage, freshness and raw output.

The normal change path is deliberately small:

```text
old-path discriminator
→ Module Proof
→ affected real Edge/Integration Proof
→ Product Pulse only when the changed property crosses the product path.
```

Sections I18.8–I18.52 form a conditional profile catalogue, not a cumulative checklist. A specialized profile is loaded only through:

```yaml
SpecializedProfileActivationReceipt:
  changed_property_and_impact_evidence:
  selected_profile_and_exact_trigger:
  omitted_profiles_and_why_they_are_irrelevant:
  expected_additional_failure_class_or_proof:
  budget_resource_and_stop_condition:
```

No test exists merely because this book names it. If a profile cannot distinguish a relevant failure or support a declared proof level, it is not selected.

