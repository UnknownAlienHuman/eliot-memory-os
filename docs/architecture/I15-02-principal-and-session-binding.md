## I15.2. Principal and Session binding

Principal identity is issued by Kernel, never self-declared.

Binding uses:

```text
launch nonce;
pipe ACL/user/service SID;
bridge installation identity/hash;
host session metadata;
capability token;
Authority Epoch.
```

Unverifiable principal receives read-limited/advisory profile or rejection.

