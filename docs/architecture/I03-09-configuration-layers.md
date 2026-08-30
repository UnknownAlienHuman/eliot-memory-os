## I3.9. Configuration layers

Precedence, from broadest to narrowest:

```text
compiled safe defaults
→ installation config
→ System Owner policy
→ WorkScope Profile
→ task/work-item policy
→ Session capability token
→ exact human approval.
```

Lower layers may narrow authority, privacy, cost or effects. They cannot expand a higher boundary unless the higher layer explicitly delegates expansion.

Files are typed TOML/JSON with generated schema; arbitrary scripts are not policy.

```text
%ProgramData%\Eliot\config\installation.toml
%ProgramData%\Eliot\config\policy.toml
%ProgramData%\Eliot\config\modules\*.toml
%LocalAppData%\Eliot\config\user.toml
<scope>\.eliot\profile.toml        optional, untrusted until admitted
```

Repository/workspace config is input, not authority. It cannot grant itself secrets, write paths or model budget.

