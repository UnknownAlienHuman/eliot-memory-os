## I15.12. External model data firewall

Before send:

```text
resolve data-class policy;
redact secrets/personal data;
minimize bundle;
preserve source labels and instruction taint;
record provider/model/retention/fallback;
enforce cost/time/tool limits;
prevent direct local DB/tool authority.
```

After response:

```text
candidate-only;
store provider receipt/cost;
scan/label output;
validate schema/lineage;
no automatic canonical promotion.
```

