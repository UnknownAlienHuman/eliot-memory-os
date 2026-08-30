## I0.14. Documentation and evidence-build integrity

Documentation integrity is proportional to the decision being made. Routine drafting must not become a release ceremony.

### Working-draft path

Normal iterative edits use:

```text
version control and one visible diff;
Markdown/reference/contract-owner lint;
current section-level review;
no mandatory audit report, ZIP, manifest or archive;
no claim that the draft is accepted or independently verified.
```

A working draft may change repeatedly. Its display version is not a Product Identity and no evidence package is required after every edit.

### Freeze/publication path

Content-addressed packaging is required only when the exact bytes become load-bearing outside the current editing episode, for example:

```text
normative-pair candidate/cutover;
external independent audit;
repository authority migration;
old-document deletion gate;
release or handoff that cites an exact document identity;
forensic/recovery archive.
```

Then the sequence is:

```text
1. Assemble immutable staging inputs.
2. Render documents and required machine ledgers once.
3. Reject unresolved template placeholders, duplicate owners and broken references.
4. Freeze bytes.
5. Compute pair identity and required evidence digests.
6. Build only the package required by the decision.
7. Re-extract that package and verify payload digests/references.
8. Publish atomically.
```

After freezing, any byte change creates a new candidate identity and invalidates only audits/packages that depended on the prior bytes. It does **not** require regenerating unrelated historical packages or a new prose audit merely to continue drafting.

`DocumentationEvidenceCheck` for a frozen decision verifies at least:

```text
current/versioned byte equality when a versioned copy is intentionally published;
manifest/package digest equality for the package actually being used;
no unresolved template sentinel;
referenced local evidence resolves by digest or declared external URI;
generated counts are recomputed from payloads;
no audit claims CURRENT_VERIFIED without executable evidence;
no normative section stores chronological audit history already held by the ledger.
```

A successful documentation check proves artifact integrity and traceability only. It is not Product Proof and cannot certify code/runtime/data conformance.

The normative pair is identified externally after both files are intentionally frozen:

```yaml
NormativePairIdentity:
  pair_key: hash(architecture_sha256, implementation_sha256)
  architecture_revision_and_sha256:
  implementation_revision_and_sha256:
  derived_contract_catalogue_or_generation_refs: # evidence only; not a third normative document
  external_requirement_and_decision_evidence_refs: # evidence only; do not change pair_key
  created_at_and_builder_identity:
  evidence_package_manifest_ref: # optional; required only when the freeze/publication decision uses a package
  supersedes_identity_ref:
```

Only the two document digests form `pair_key`. Requirements ledgers, contract catalogues, audits and packages remain evidence/projections and cannot become a third normative book.

The Implementation never contains its own final digest as authority. Handshakes, cutovers and audits use the external pair receipt. A normal working-draft edit needs no content-addressed package until one of the freeze/publication triggers occurs.

