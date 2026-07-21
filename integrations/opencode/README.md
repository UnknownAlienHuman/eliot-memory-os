# OpenCode ELIOT integration

`ELIOT_GOVERNOR_EXE` must use slash-normalized Windows syntax such as
`C:/path/to/eliot-governor.exe`. OpenCode substitutes environment variables
before parsing JSONC, so raw backslashes would become invalid JSON escapes.

Supervised launches set an ELIOT-owned isolated `XDG_CONFIG_HOME`. OpenCode's
host-managed data/auth root is unchanged, while unrelated user MCP definitions
are excluded from the bounded invocation. Interactive launches keep the normal
merged user configuration.

For an ephemeral bundle smoke, set `ELIOT_GOVERNOR_EXE` to the absolute release binary and `OPENCODE_CONFIG_DIR` to this directory, then launch the installed OpenCode CLI. OpenCode merges this additive directory with existing settings; this bundle does not set a provider, model, agent, or credential.

For ordinary persistent discovery, use `eliot-governor host install --host opencode`. It installs one local MCP server, one compact always-on bootstrap instruction, four on-demand portable skills, and a bounded lifecycle plugin while preserving provider/auth and unrelated JSONC. Without an attached ELIOT task the plugin is passive. Use `host uninstall --host opencode` for receipt-backed rollback; merely omitting `OPENCODE_CONFIG_DIR` only disables an ephemeral bundle smoke.
