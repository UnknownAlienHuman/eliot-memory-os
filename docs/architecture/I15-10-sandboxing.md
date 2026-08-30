## I15.10. Sandboxing

Process modules receive:

```text
restricted working directory;
allowlisted environment;
scoped filesystem roots;
network policy where practical;
Job Object limits;
no inherited handles/secrets except explicit;
separate scratch/worktree for mutating workers.
```

Windows sandboxing limits are documented honestly. Stronger isolation may use Windows Sandbox/VM/container/cloud module for untrusted workloads.

