## I16.3. Composite run trace context

Every run/event carries the applicable lineage:

```text
trace_id and operation_id;
task/work item/attempt/job;
principal/session/controller;
WorkScope and State Fence;
adapter instance and process/job-object identity;
native session/run and parent-child agent locators;
requested and actual RouteFingerprint receipt;
worktree and ExecutionEnvironmentLease;
module/process generation and Authority Epoch;
event sequence/cursor and normalization version;
impact/recipe/assurance class.
```

Secrets/content are not span labels. Logical run state, process state, provider state and event cursor are independent observables.

