## I18.25. Evolution of the testing system

Testing modules improve through the same evidence loop:

```text
escaped defect or false block
→ identify missing/wrong discriminator
→ update module/profile/parser/impact edge candidate
→ run historical replay and held-out case
→ canary on affected task family
→ promote, narrow or reject
→ retire superseded tests.
```

The system must not react to every defect by adding a permanent global test. The preferred repair is the smallest reusable discriminator at the actual owner boundary.

