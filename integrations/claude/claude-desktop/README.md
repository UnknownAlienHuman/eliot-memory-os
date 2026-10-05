# ELIOT for Claude Desktop

This is a Desktop Extension/MCPB integration, distinct from the Claude Code plugin
under `../eliot`.

The packaged server is `server/eliot-agent-bridge.exe` (bins/eliot-agent-bridge, not the production Governor). It serves the admitted SPINE_FUNCTIONAL contour through the Kernel front door over stdio; it constructs no Governor, Store, WAL, or writer objects. The package contains no database, credentials,
project files, provider configuration, or permanent role assignment.

Build from the repository root:

```powershell
cargo build --locked --release -p eliot-agent-bridge --bin eliot-agent-bridge
scripts/build-claude-desktop-extension.ps1
```

The script stages the release binary, validates and packs the extension with the
pinned official `mcpb` CLI, and writes package hashes plus a context footprint
report under `%LOCALAPPDATA%\Eliot\packages\claude`. The package name is
`eliot-<version>-windows-x64.mcpb`.

The Desktop extension version is independent from the Governor application
version. If the embedded Governor hash changes, the build refuses to reuse an
existing extension version; bump `mcpb/manifest.json` before packaging so Claude
Desktop can distinguish and update the installed bytes.

Install and activate through Governor, which opens the official Claude Desktop
review dialog and verifies the extension registry and installed server hash before
writing its receipt:

```powershell
& $governor host install --host claude-desktop
& $governor host activate --host claude --surface desktop
& $governor host doctor --host claude
& $governor host uninstall --host claude-desktop
```

Do not edit `claude_desktop_config.json`. Provider authentication is outside the
installer boundary. If the official dialog remains disabled as `Loading...`, the
command times out without a receipt or configuration mutation; inspect Claude's own
extension-state log before retrying.
