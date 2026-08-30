## I11.8. Authentication

The primary WinUI client authenticates through the interactive User Broker and authenticated local IPC. The binding includes Windows user/session identity, UI process identity, a short-lived Kernel challenge/session token, requested Human role and exact ControlBoard/Operator capability set. UI restart creates a new operational binding and never revives authority from cached application state.

State-changing requests require an explicit authenticated Human principal and the same typed authority/approval contracts as CLI or agent surfaces. Recovery operations may require a one-shot local CLI/Recovery Principal confirmation token. The optional loopback web compatibility viewer, when enabled, uses a separate short-lived browser token bound to user SID, Origin validation and CSRF protection; it is disabled by default and cannot expose a wider capability set than the native UI.

