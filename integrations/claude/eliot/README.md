# Claude Code ELIOT integration

`eliot-governor host install --host claude` installs this self-contained plugin at
`~/.claude/skills/eliot`. Claude Code then discovers exactly four namespaced skills,
one ELIOT MCP server, and bounded native hooks without a settings-file edit. The
plugin does not choose a model, provider, default agent, or credential source.
`SessionStart` contributes one short availability pointer; it grants no role and
loads no architecture body.

Use `eliot-governor host doctor --host claude` and
`claude plugin validate --strict <installed-directory>` before launch. Managed
`host launch` reuses the installed plugin when its bundle and Governor hashes match;
`--plugin-dir` is only a fallback before installation or after detected drift. For
isolated compatibility tests add `--mcp-config <installed-directory>/.mcp.json
--strict-mcp-config`. Remove it through Governor so the ownership receipt and
rollback checks are enforced.
