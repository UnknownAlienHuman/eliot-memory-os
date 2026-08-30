## I19.2. Current forensic baseline and refresh rule

Historical audits and live-test artifacts are retained in the external evidence ledger as candidate regressions and donor evidence. They are not the current baseline by filename. Before every repair or migration campaign, `CurrentSystemEvidenceSnapshot` binds the exact selected source head, installed artifacts, live store revision and active integrations; only that snapshot can classify a blocker as current.

Candidate migration blockers that must be rechecked rather than assumed closed or current:

```text
weak legacy finish alongside canonical finish;
lossy generic payload transport;
report-backed shadow authority and multiple writer composition paths;
no enforced single Product Identity;
normal recall/understanding and live curation not operationally proven;
hooks/Skills are partial and host-dependent;
test/status/report activity has repeatedly exceeded product evidence.
```

Before each repair campaign, source facts are refreshed against the exact selected head, installed artifacts, live DB revision and active integrations. A historical audit finding receives one disposition:

```text
CURRENT(owner, discriminator, acceptance);
FIXED(commit/generation, discriminator);
SUPERSEDED(accepted Architecture/Implementation decision);
NOT_REPRODUCIBLE(replay evidence);
FALSE_POSITIVE(reason).
```

No finding disappears because a later report omitted it.

Required outputs:

```text
accepted Product Identity manifest;
component/owner/path inventory;
P0/major finding ledger with dispositions;
current data/integration inventory;
repair impact graph;
first Product Proof plan.
```

