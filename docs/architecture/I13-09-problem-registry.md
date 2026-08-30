## I13.9. Problem Registry

```yaml
ProblemState:
  problem_id:
  class: operational | integration | cognitive | data_quality | security | cost
  severity:
  scope/affected_dependencies:
  symptom:
  evidence:
  hypotheses:
  owner_and_epoch:
  containment:
  repair_history:
  next_probe_or_action:
  resolution_condition:
  state: open | triaged | diagnosing | contained | repairing |
         verifying | resolved | accepted_risk | superseded | quarantined
  reopen_history:
```

Notification/restart is not resolution.

Problem ownership is lease/epoch-bound. If the owner Session, agent, Module or Human delegation disappears, the Problem remains open, the old owner is fenced, and ownership becomes `unassigned` until reassigned to an eligible successor or escalated through Critical Attention. Loss of the owner never implies resolution or acceptance of risk.

### Semantic contamination versus structural corruption

```text
semantic_contamination
  records/interpretations/procedures may be wrong or poisoned while ordering,
  provenance and storage integrity remain intact;

structural_corruption
  canonical ordering, receipts, provenance, schema/storage integrity or authority
  state cannot be trusted.
```

Semantic contamination is handled by scoped quarantine, contest/reweighting, influence-dependency revocation, Dreamer/Concilium audit, practical tests and forward correction. Raw source and forensic history remain. A large or uncertain contamination event may clone a snapshot into an isolated candidate canonical-store generation for swarm analysis and clean cutover, but restore is not treated as epistemic proof.

Structural corruption closes affected writes, opens an Incident and uses isolated restore/rebuild/break-glass contracts. Backups and Git-like history are recovery instruments; they do not decide which theory is correct.

