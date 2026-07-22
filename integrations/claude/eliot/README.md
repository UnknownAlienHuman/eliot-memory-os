# Claude Code ELIOT integration

`eliot-governor host install --host claude` stages this self-contained plugin in
the external ELIOT package cache and installs `eliot@eliot-local` through Claude
Code's official local-marketplace lifecycle. Claude Code then discovers exactly
four namespaced skills, one ELIOT MCP server, and bounded native hooks without a
settings-file edit. The plugin does not choose a model, provider, default agent,
or credential source. `SessionStart` contributes one short availability pointer;
it grants no role and loads no architecture body.

Use `eliot-governor host activate --host claude --surface code`, family doctor,
and `claude plugin validate --strict <installPath-from-plugin-list>` before
launch. Managed `host launch` reuses the installed plugin when its bundle and
Governor hashes match; `--plugin-dir` is only a fallback before installation or
after detected drift. An explicit MCP config remains a debug-only compatibility
fallback. Remove the plugin through Governor so the official lifecycle and
ownership receipt remain consistent.
