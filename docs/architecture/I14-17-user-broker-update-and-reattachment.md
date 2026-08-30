## I14.17. User Broker update and reattachment

User Broker binaries are immutable per generation and are never replaced in place inside a logged-on session.

```text
stage candidate artifact and authorization policy
→ start candidate with no launch/effect authority
→ authenticate SID/session/artifact and verify EBP contract
→ create a higher/new-lineage UserBrokerEpoch
→ fence old registration from new launches
→ transfer only explicit broker-independent Session bindings
→ let old exact operations drain or reconcile; terminate its Job Object
→ publish registration/cutover receipt.
```

Existing child runtimes stay pinned to the broker/epoch that launched them until their operation is completed, cancelled or marked unknown; they are never silently adopted by a new broker. Logout or inability to prove old Job Object termination stops cutover and requires reconciliation.

