## I21.6. Source portfolio, coverage denominator and CoverageReceipt

```yaml
SourcePortfolio:
  primary_sources_and_specifications:
  reviews_and_secondary_analyses:
  operational_and_measured_evidence:
  independent_implementations:
  critical_or_negative_sources:
  missing_source_classes_and_reason:
  independence:
    source_family | provider_family | evaluator_family |
    shared_context_ancestor | shared_assumptions
```

Ten pages from one vendor are not ten independent sources. Two outputs are dependent when they share a source, restate one primary work, run on one model family, saw one parent summary, use one evaluator or inherit one mistaken assumption.

```yaml
CoverageReceipt:
  requested_scope_and_frozen_scope_snapshot:
  eligible_represented_cited_and_omitted_sources:
  unknown_coverage_and_reason:
  source_families_and_independence_profile:
  routes_used_stale_and_skipped:
  provider_degradation_and_redacted_dependencies:
  counter_search_status:
  denominator_kind: complete_scope | sampled_with_method | unknown
  budget_limitations:
  terminal_disposition:
```

`denominator_kind = complete_scope` is the only basis on which a scoped absence may be claimed. An indexed top-k result never narrows the denominator of an exact negative claim: it proposes candidates, and completeness is proved on the frozen scope. Retrieval quality and citation quality are separate obligations — see I21.8.

