# ELIOT for Claude Desktop

This is a Desktop Extension/MCPB integration, distinct from the Claude Code plugin
under `../eliot`.

The packaged binary is the same release `eliot-governor.exe` used by other hosts. It
runs only the stdio facade with `--host claude-desktop --instance default`; the facade
reuses or starts the one user-mode default Governor and connects through the existing
authenticated Windows named pipe. The package contains no database, credentials,
project files, provider configuration, or permanent role assignment.

Build from the repository root:

```powershell
cargo build --release -p eliot-app
scripts/build-claude-desktop-extension.ps1
```

The script stages the release binary, validates and packs the extension with the
official `mcpb` CLI when it is available, and writes package hashes plus a context
footprint report under `dist/claude`. The package name is
`eliot-<version>-windows-x64.mcpb`.

Install and uninstall through Governor, which opens the official Claude Desktop
review dialog and verifies the extension registry and installed server hash before
writing its receipt:

```powershell
.\target\release\eliot-governor.exe host install --host claude-desktop
.\target\release\eliot-governor.exe host doctor --host claude-desktop
.\target\release\eliot-governor.exe host uninstall --host claude-desktop
```

Do not edit `claude_desktop_config.json`. Provider authentication is outside the
installer boundary. If the official dialog remains disabled as `Loading...`, the
command times out without a receipt or configuration mutation; inspect Claude's own
extension-state log before retrying.
