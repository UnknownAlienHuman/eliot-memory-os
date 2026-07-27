# ELIOT Governor Antigravity Plugin

Official Antigravity plugin source for the compact Part-E ELIOT memory surface
and authority rules.

The plugin contains four canonical skills and intentionally contains neither a
custom main agent nor `mcp_config.json`. ELIOT MCP is registered separately with
an absolute release-binary path and `--host antigravity`; Governor binds the
session to the host-neutral `dynamic_agent` profile. Host identity grants no
task role.
