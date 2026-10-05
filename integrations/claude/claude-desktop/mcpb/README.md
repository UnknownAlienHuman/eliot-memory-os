# ELIOT Governor MCPB

This Windows x64 bundle connects Claude Desktop to the ELIOT Kernel front door through the packaged `server/eliot-agent-bridge.exe` bridge over stdio. It contains one release bridge binary, no database, no provider credentials, and no project data. The bridge constructs no Governor, Store, WAL, or writer objects.

Installation is owned by Claude Desktop's official custom-extension UI. The
Governor may open this package and observe only ELIOT-owned installation state;
it does not edit `claude_desktop_config.json` or bypass the confirmation dialog.

The live surface is role-neutral and compact. A Claude identity grants no task
role, lease, mutation scope, verification authority, or completion status.
