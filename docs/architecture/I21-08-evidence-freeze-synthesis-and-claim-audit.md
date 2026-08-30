## I21.8. Evidence freeze, synthesis and claim audit

Before prose synthesis the accepted evidence revision is frozen:

```yaml
EvidenceFreeze:
  freeze_id_and_state_fence:
  contract_and_protocol_digests:
  included_evidence_refs:
  excluded_evidence_and_reasons:
  unresolved_contradictions:
  open_research_debts:
  frozen_at:
```

A synthesis author may not silently acquire a new fact and include it without admission. Any new material reopens the freeze with a recorded reason.

Every material statement of a released artifact carries a resolved chain:

```text
claim → evidence handle → source revision → run/measurement → transformation → statement.
```

`ClaimAudit` checks four independent properties: reference verification, value/measurement verification, specification compliance and method–artifact alignment. Its output classifies each claim as `SUPPORTED`, `PARTIALLY_SUPPORTED`, `UNSUPPORTED`, `CONTRADICTED` or `NOT_VERIFIABLE_IN_SCOPE`; uncertainty and scope limits are preserved rather than smoothed.

Retrieval quality and citation quality are separate obligations and are reported separately:

```text
source_satisfies_requirement    the admitted source genuinely contains the required evidence;
excerpt_supports_requirement    the supplied exact excerpts alone are sufficient for a careful
                                reader to verify the requirement.
```

A result may satisfy the first and fail the second. Failure modes of the second are explicit: fabrication, paraphrase that shifts meaning, stitching across sections, cropping that removes a hedge or negation, a search snippet presented as a page quote, and an excerpt absent from the admitted revision.

A model cannot mint a citation, source ID, URL, line range or support relation through prose; this is the reference firewall of I21.7.

