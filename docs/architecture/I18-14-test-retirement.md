## I18.14. Test retirement

Remove or narrow a test when:

```text
contract no longer exists;
a cheaper proof subsumes it;
false failure/maintenance cost exceeds value;
it encodes abandoned implementation rather than behavior;
it duplicates the same discriminator without new coverage;
it cannot fail on the actual production path.
```

Evidence and rationale are retained. Test count is never protected.

