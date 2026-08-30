## I7.3. Handshake

```text
ClientHello:
  protocol range;
  module/bridge identity;
  artifact hash;
  launch nonce;
  capabilities;
  State/Authority Epoch;
  privacy classes;
  max frame.

ServerHello:
  selected protocol;
  session/principal binding;
  allowed capabilities/effects;
  config snapshot;
  heartbeat;
  control channel;
  rejection reason if incompatible.
```

Module self-assertion is checked against the Module Catalog, Generation Registry and Capability Registry evidence. Old generation cannot reconnect after epoch fencing.

