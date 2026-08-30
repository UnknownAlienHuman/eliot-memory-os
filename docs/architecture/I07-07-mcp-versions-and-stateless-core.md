## I7.7. MCP versions and stateless core

Primary MCP version: final 2026-07-28 through the official `rmcp` 3.1.x compatibility line; 3.1.2 is the current source-verified candidate and remains unadmitted until local bridge/conformance proof. The core protocol is stateless: ELIOT never derives durable Session, authority or continuity from an MCP connection or initialize handshake. Any selected patch is pinned only after ELIOT dual-version conformance, because SDK wire regressions must not leak into domain/session semantics.

Each request maps through a Kernel-owned `ActiveSessionBinding` in ORS, created from a scoped local credential plus canonical request metadata/tool input. The durable ELIOT Session and immutable attach/detach receipts remain canonical; the active transport binding is operational and never revives from backup. A long-lived stdio process is only a transport optimization. MCP Tasks are optional; when absent, ELIOT returns the same Durable Job handle/resource and polling/subscription contract.

The 2025-11-25 compatibility adapter may use transport/session hints for correlation, but maps them to the same ELIOT Session and cannot create authority or task identity. Version-specific behavior remains isolated in `eliot-mcp`.

MCP 2026-07-28 has a stateless protocol core. `AgentSession` in ELIOT is application state bound by explicit authenticated attach metadata; it is not inferred from a transport connection or an MCP initialize session. Reconnect, stdio restart and HTTP requests therefore reuse an explicit ELIOT session/task binding. MCP Tasks are used only when the client advertises the extension; otherwise ELIOT exposes its own Durable Job handle.

