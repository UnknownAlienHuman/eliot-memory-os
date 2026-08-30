## I13.5. State/revision conflicts

```text
stale expected revision → reject effect, preserve observation/candidate;
old Authority Epoch → reject as fenced;
overlapping write/effect sets → serialize or create plan conflict;
unknown commit → resolve receipt before retry;
partial multi-scope outcome → saga state and compensation.
```

