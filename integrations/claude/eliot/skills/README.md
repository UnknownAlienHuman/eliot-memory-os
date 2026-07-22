# Generated skill copies -- do not edit

Every `SKILL.md` under this directory is a byte-for-byte copy of
`integrations/agent-skills/<name>/SKILL.md`, written by:

```
just sync-skills
```

Edit the canonical body under `integrations/agent-skills` and re-run that
command. Editing a file here is silently reverted by the next sync, and
`SkillPackService::lint` fails the build in the meantime.
