# Eliot Governor Codex Plugin

This bundle exposes the governed Eliot MCP server, lifecycle hooks, and task skills for the local `eliot-governor` project.

Stage the current Rust binary into the distributable bundle and validate it:

```powershell
.\install-local.ps1
```

Verify the bundle and reports:

```powershell
.\verify-plugin.ps1
```

This script does not mutate the Codex plugin marketplace, global config, hook
trust, or authentication state. The bundle MCP server and hooks execute
`bin/eliot-governor.exe`; hooks resolve the installed bundle with `PLUGIN_ROOT`.
Set `ELIOT_GOVERNOR_CONFIG` to an initialized runtime configuration before use.
Hook records remain bounded by that configuration's owned runtime root.
