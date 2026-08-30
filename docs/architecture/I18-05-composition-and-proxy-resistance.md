## I18.5. Composition and proxy resistance

Visible local tests are optimization signals and may be gamed. Long-horizon or cross-module acceptance includes at least one applicable countermeasure:

```text
held-out composition scenario;
independent or blind evaluator;
real downstream consumer/artifact;
metamorphic/property test over unknown inputs;
canary on actual runtime;
cross-feature state interaction;
base/candidate differential proof;
Human acceptance for properties no instrument can measure.
```

The test must fail on the exact old production path, not merely on a fixture created after the repair. Test quantity never compensates for wrong construct, wrong owner or wrong runtime identity.

Oracle separation:

```text
agent changing implementation may add a discriminator that reproduces the old fact;
changing expected business/contract behavior in the same unit requires
  an independent contract/oracle owner or mechanically anchored evidence;
snapshot acceptance is a separate disposition, never an automatic update;
a worker cannot make its implementation pass by weakening the verifier,
  broadening tolerance or changing fixture truth without explicit review.
```

