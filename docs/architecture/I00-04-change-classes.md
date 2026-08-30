## I0.4. Change classes

| Class | Example | Decider | Minimum verification |
|---|---|---|---|
| Local | UI text, isolated parser, report format | Module owner | Module checks |
| Compatible Module | new Module generation without state migration | Module owner + supervisor policy | contract + affected integration + canary |
| Cross-module | protocol field, shared contract, dependency edge | integration owner | affected graph + compatibility suite |
| Load-bearing | Kernel, store semantics, authority, ORS, security boundary | System Owner + architecture/conformance review | dedicated fault/migration suite |
| Release | published installation | release owner | full release gate |
| Architecture-impacting | changes Intent or Hard Boundary | Architecture Owner | Architecture revision before code promotion |

### Normative pair and evidence artifact identity

Only `ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` form the normative pair. Audits, research, migrations, benchmarks, and generated projections are evidence artifacts: they may disprove a support claim, open a gap, or propose a change, but gain no normative force from name, date, completeness, or citation count.

```yaml
NormativePairDocumentIdentity:
  document_id:
  role: architecture | implementation
  semantic_version:
  sha256:
  predecessor_sha256:
  paired_document_sha256:
  generated_at:
  status: candidate | accepted | superseded | invalidated

EvidenceArtifactIdentity:
  artifact_id:
  role: audit | research | migration_evidence | benchmark | generated_projection
  sha256:
  source_identity_refs:
  scope_and_validity:
  evidence_class_and_execution_status:
  owner_and_disposition:
  invalidation_and_expiry:
```

Hard rules for an intentionally frozen or published revision:

```text
`ELIOT_IMPLEMENTATION.md` and its published versioned copy are byte-identical;
any byte change after freeze creates a new identity and invalidates only verdicts bound to the prior digest;
an audit or PASS applies only to the exact source identities and scope it names;
Architecture/Implementation projections, Skills and agent packets carry the exact normative-pair identity they were compiled from;
no agent may combine sections from two frozen Implementation digests as one current contract;
an EvidenceArtifactIdentity can narrow or invalidate a support claim, but cannot change Architecture/Implementation without the applicable governed document revision.
```

A working draft may change under version control without minting a content-addressed identity or incrementing the display version after every edit; it acquires an identity only at the freeze/publication boundary of I0.14. The pair identity is emitted externally after both files are frozen. This prose never embeds or hand-maintains its own digest.

Normative identifiers, schemas, wire values, reason codes and generated RuleCatalogue entries use English. Explanatory prose may be Russian or English, but one classified rule block and one generated agent instruction are language-homogeneous. Translation is a projection carrying the exact source rule ID/revision; it is not a second contract. Context measurements use the tokenizer of the actual rendered language rather than assuming STU equivalence.

