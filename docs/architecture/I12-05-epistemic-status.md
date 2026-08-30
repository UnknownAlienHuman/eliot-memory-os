## I12.5. Epistemic status

```text
observed;
supported;
verified;
contested;
stale;
superseded;
rejected;
unknown.
```

A rendered material statement also carries an object-local label set; the labels do not replace the canonical status above and are not mutually exclusive truth states:

```yaml
StatementLabelSet:
  basis: SOURCE_SUPPORTED | DERIVED_INFERENCE | HYPOTHESIS | EDITORIAL_RECOMMENDATION
  conditions: [CONTESTED | UNRESOLVED | REDACTED_DEPENDENCY]
```

`basis` states how the sentence is being presented; `conditions` state why it cannot be read as an uncontested live assertion. A source-supported statement may also be contested, and a hypothesis may remain unresolved. `REDACTED_DEPENDENCY` means a load-bearing support handle was purged/redacted and forces withdrawal or revalidation under the existing dependency graph. Citation eligibility remains owned by the exact evidence/reference path in I21.7: model prose cannot mint a citation identifier, and every emitted citation resolves to an admitted live evidence handle and allowed reference entry.

`verified` requires applicable Evaluation Contract and current VerificationRun. Model summary cannot upgrade.

Separate axes:

```text
support/status;
assertability: ASSERTABLE | NON_ASSERTABLE_UNVERIFIED | ABSTAIN_OR_FENCE;
accessibility/activation;
allowed influence;
physical existence;
source security/taint.
```

A claim may be mentionable as historical/third-party content while remaining non-assertable. Third-party-only, stale, contested or absent support cannot be rendered as an ELIOT assertion; the Decision Safety Floor records the support handles and returns `ABSTAIN_OR_FENCE` or a narrower attributed statement. Mixed-provenance transformations inherit the minimum allowed assertability/influence of their supporting sources unless a registered verified transition changes it.

