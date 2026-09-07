# START HERE

Read this file first. It is the shortest complete path from a cold start to a
merged change. It does not replace `AGENTS.md`, `WORKFLOW.md` or the normative
pair; it tells you which of them you actually need for the task in front of you.

## 1. Current phase — draft product, code first

The product does not run end to end yet. **The priority is writing the missing
code and landing it on `main`**, not proving the code that is already there.

    44 capability cells declared      2 implemented
    318 open issues                   42 open pull requests
    134 tests ignored (need a live runtime)

Consequences for how you work, in order of importance:

1. **Write implementation, not test scaffolding.** A cell needs enough tests to
   show it does what its issue says. It does not need an exhaustive negative
   matrix before the product has ever started. Tests that prove an unbuilt
   system are deferred work, not progress.
2. **Land on `main` quickly.** A branch that lives longer than its own work is
   a liability. Merge, delete the branch, move on.
3. **Do not accumulate on disk.** No stray `target/` directories outside the
   configured shared one, no long-lived worktrees, no local-only branches. One
   worktree per active task, removed when the task ends.

## 2. Cold start — six commands

```bash
git fetch origin --prune
git rev-list --count HEAD..origin/main        # must print 0; if not, fast-forward
gh issue view <N> -R UnknownAlienHuman/eliot-memory-os --json title,body
git switch --detach origin/main
git switch -c work/<N>-<short-slug>           # ^(work|fix|docs|chore|refactor|test)/[0-9]+-[a-z0-9-]+$
cargo check -p <package> --all-targets
```

Existence of any path is checked with `git ls-tree -r --name-only origin/main`,
never with `ls` — the Windows filesystem is case-insensitive and git is not, and
a local working copy can be behind.

## 3. The rules that actually block a merge

- One issue, one branch, one PR. The branch name carries the issue number.
- `Implements #N` in the PR body. `Closes #N` only when the issue is fully done.
- Exclusive mutable scope: touch only the paths your issue owns. If two issues
  write one file, say so in the PR body and agree an order — do not race.
- Do not edit an issue's acceptance to match what you built.
- Never claim a check you did not run. If build, tests or lint were not
  executed, say so in the PR body in one sentence. An honest gap is mergeable;
  a false claim is not.

## 4. Where the documentation is, and when you need it

| You are doing | Read |
| --- | --- |
| any change at all | this file, then `AGENTS.md` |
| branch/worktree mechanics | `WORKFLOW.md` |
| a capability cell | the issue body, then the cell's `module.toml` |
| something touching contracts or the wire | `docs/ARCHITECTURE_CONTRACT.md` and the named shard only |
| finding the owner of a file | `docs/PROJECT_MAP.md` |
| running a repository script | `scripts/README.md` |

The full verified-reading protocol in `docs/architecture/READING_PROTOCOL.md`
routes documentation for contract-level changes. It is expensive. Use it when
you are changing a contract, not when you are filling in an implementation whose
contract already exists.

## 5. Finishing

```bash
cargo check -p <package> --all-targets        # must pass
cargo test -p <package>                       # run it; report the number
git push -u origin work/<N>-<slug>
gh pr create --base main --title "[<UNIT>] <what>" --body "Implements #N ..."
gh pr merge <PR> --squash --delete-branch      # when green and reviewed
```

Then remove your worktree. Nothing regenerable stays on disk.
