## A12.2. Principal, Session, and Visibility

Identity is not a model's self-declared string. The harness or installation boundary establishes the principal and binds it to a Session, WorkScope, capabilities, visibility, and Authority Epoch.

Conceptual Session lifecycle:

```text
attach → active → suspended → detached | expired | revoked.
```

Every read, Active View, model bundle, notification, and write is filtered by principal, WorkScope, visibility, and policy. Unknown identity means minimum privilege and no Material authority.

