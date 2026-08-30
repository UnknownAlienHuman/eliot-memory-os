## I11.1. First UI

DEFAULT: a Windows-native WinUI 3 desktop application on the stable Windows App SDK line. The first target is Windows App SDK 2.3.1, admitted only after packaging, startup, update, accessibility and recovery tests on the supported Windows 11 profile.

Stack and boundary:

```text
thin C# WinUI 3/XAML client in the interactive user session;
Windows App SDK stable runtime and native app notifications;
authenticated EBP/ControlBoard/Operator client through User Broker;
no Electron/Tauri and no public network bind;
no database, package-manager, provider credential or canonical state ownership;
Rust Host/Kernel/eliotd remain the control plane.
```

The UI provides Dashboard, Dreamer chat, WorkScope/onboarding, agent/swarm launcher, settings, maintenance, problems, evidence and recovery views. It uses native Fluent/WinUI interaction patterns, light/dark and high-contrast modes, high-DPI scaling, keyboard navigation, screen-reader labels and progressive disclosure: ordinary users see the decision and safe next action, while exact receipts/IDs remain expandable. Visual polish cannot hide degraded capability behind a green state. UI actions compile typed operator intents; the UI does not invent commands or call agent binaries directly.

The single canonical CLI `eliot.exe` (`eliot`) is the mandatory administrative, automation and recovery fallback. It is **not** an ELIOT coding-agent/provider CLI: ELIOT launches and supervises installed external agents through their own runtimes and bridges.

`eliot dashboard` MAY provide a lightweight terminal surface using Ratatui + Crossterm. It renders the same role-filtered `ControlBoardView` and owns no state. An optional loopback web viewer may be added for compatibility or remote-view experiments, but it is not the primary Windows UI and cannot expose more authority than the native client.

