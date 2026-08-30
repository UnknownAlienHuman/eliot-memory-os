## I18.22. Flake, hang and recurrence handling

A flake report requires actual repetitions or statistically meaningful historical observations; it is never synthetic.

Distinguish:

```text
build failure;
launch failure;
test assertion failure;
timeout/hang;
infrastructure/resource failure;
parser/evidence failure;
intermittent outcome.
```

Quarantined tests remain visible with owner, reason, expiry/review and replacement proof. Retry cannot turn an initial failure into a clean pass without preserving both attempts and policy.

