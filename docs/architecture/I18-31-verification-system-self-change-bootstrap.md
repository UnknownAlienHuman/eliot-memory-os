## I18.31. Verification-system self-change bootstrap

A changed verifier cannot be the sole authority proving its own correctness. Changes to ProcessExecutor, InstrumentRunner, profile selection, parsers, evidence normalization, test discovery or FinishService use an asymmetric bootstrap:

```text
last-known-good runner/harness
→ executes the unchanged external discriminator and candidate contract suite;

candidate runner/module
→ processes the same raw fixture/tool evidence in shadow;

comparison
→ checks raw capture, normalized meaning, selection, omissions and outcome;

canary
→ runs bounded real tasks while old generation remains rollback-capable;

cutover
→ occurs only after independent evidence and a new generation receipt.
```

Special cases:

```text
ProcessExecutor change
  → an outer Host/OS-level guardian scenario verifies tree cleanup and evidence;

parser change
  → old raw corpus is replayed through old and candidate parsers;

selection/impact change
  → historical escapes plus sentinel lanes test false negatives;

FinishService/verifier binding change
  → forged/partial proof adversarial suite runs through the last-known-good public front door.
```

The old generation may reject a candidate; it cannot certify that its own mechanism is permanently correct. A Human or independent route decides unresolved oracle conflict. This bootstrap is invoked only for the verification/control surface being changed, not as a full release cycle for unrelated modules.

Documentation/audit tooling uses the same asymmetric rule. `DocumentationEvidenceCheck` is executed from a frozen outer script/generation and verifies the exact bytes it packages. Its negative corpus includes:

```text
post-manifest one-line mutation;
Markdown digest changed but JSON ledger stale;
unresolved template variable in a published audit;
missing referenced artifact;
manifest points to a different versioned copy;
ZIP payload differs from workspace file;
count/table generated from a different source revision;
CURRENT_VERIFIED claim with no executable evidence;
two public contract sections define the same trait/type with different AST or schema digests;
a receipt payload redefines identity/authority/fence/provenance fields owned by `ReceiptEnvelope`;
an unknown additive reason code fails to round-trip under its stable `AgentResponseDisposition`.
```

The candidate documentation generator cannot certify itself solely by emitting a green report. Package re-extraction and digest comparison are mandatory, and any post-package edit creates a new revision.

