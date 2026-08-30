## I18.23. Agent development test protocol

Before code, the worker receives:

```text
primary micro-module and public contract;
exact old failing behavior or missing property;
selected InstrumentProfile and independent module test command;
affected contract edges and forbidden drive-by changes;
expected observable and stop condition.
```

Worker flow:

```text
run discriminator;
change only declared module/support scope;
run module proof;
return artifact, diff, InstrumentRun handles and unresolved gaps;
do not run full suite unless selected by Impact Plan;
do not alter the test to accept new output without separate oracle review;
if the brief/discriminator is wrong, return ContractChallenge instead of optimizing to it.
```

Integrator runs edge/integration proof. Blind reviewer checks causal property and omitted coverage. The applicable evaluator establishes the proof ceiling; the `Requester / Domain Owner` accepts or rejects the claimed user outcome, while the Task Controller may only propose the task disposition within its delegated acceptance contract.

