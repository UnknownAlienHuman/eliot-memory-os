## I13.8. Attention ownership

Default owners:

```text
task issue → Task Controller;
security/integrity → System Owner/Recovery Principal;
architecture gap → Architecture Owner;
verifier/evidence gap → WorkScope Owner or Task Controller;
module health → module owner/Doctor;
budget → Requester/System Owner according to policy.
```

Lost owner triggers reassignment/escalation with new Authority Epoch.

