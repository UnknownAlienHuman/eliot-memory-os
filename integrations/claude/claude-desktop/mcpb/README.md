# ELIOT Governor MCPB

This Windows x64 bundle connects Claude Desktop to the existing per-user ELIOT
Governor over its authenticated local stdio facade. It contains one release
`eliot-governor.exe`, no database, no provider credentials, and no project data.

Installation is owned by Claude Desktop's official custom-extension UI. The
Governor may open this package and observe only ELIOT-owned installation state;
it does not edit `claude_desktop_config.json` or bypass the confirmation dialog.

The live surface is role-neutral and compact. A Claude identity grants no task
role, lease, mutation scope, verification authority, or completion status.
