# Continuation sprint after the 2026-10-02 swarm stop

Owner order (2026-10-02 12:30), verbatim:

> Сделай отдельный PR на продолжение работы. Его задачей должна быть: 1) Ознакомление. 2) Повторный аудит блокеров.
> 3) Доработка Issue при необходимости. 4) Составление нового плана работы. Нужно будет работу разделить таким
> образом, чтобы агенты могли выполнить задачу по завершению всех этих "можно доделать" без пересечений. 5) Составить
> план сшивания, доработки контрактов. 6) Еще раз все проверить. 7) Запустить swarm и приступать к спринту.
> P.S. SpaceBunny будет отключена в течении трех дней. Времени мало.

This pull request is the work order. Its planning outputs (steps 2-6) are committed to this branch under
`workstreams/swarm/`; the PR is merged when step 6 passes, then step 7 starts the sprint.

## Inputs (all in `workstreams/swarm/` on main)
- `HANDOFF.md` - state at the stop: entry points, scripts and loops, lane states, open problems, decisions waiting.
- `BLOCK-MAP.md` / `BLOCK-MAP.tsv` - every open issue: remaining items DONE / FINISHABLE / BLOCKED, each BLOCKED item
  with its blocker (`#<issue>` or `MISSING-CONTRACT <doc:section>`), built by the lanes and audited by OR.
- `RECOMMENDATIONS.md` - root's lessons (in Russian): what made the last sprint slow and how to avoid it.
- `MANAGER-BRIEF.md` - the swarm operations manual and decision log (Russian).
- Local, on the owner's machine: control folder `C:\Development\Rust\projects\eliot-swarm\control-20260923-impl\`
  (scripts in `v2\`) and the scripts package in the owner's Downloads.

## Time box
Space Bunny (7 of the 10 lanes: W1-W3, OR, W4, CB, CB2) goes away within three days of 2026-10-02. Steps 1-6 must
take hours, not days. Remaining capacity after that: Codex gpt-6.1-sol managers with gpt-6-luna sub-agents (limit 5),
Muse Code (MC, quota back 2026-10-05 00:00 UTC), Antigravity (little quota), Claude.

## Steps
1. **Familiarisation.** Read the inputs. Every issue is read with ALL its comments (`gh issue view <n> --comments`)
   plus the canonical documentation it names (`python scripts/docs_read.py read ...`, see `AGENTS.md`). Never work
   from a summary of an issue.
2. **Re-audit the blockers.** For every BLOCKED item in `BLOCK-MAP.tsv` (start with the rows listed under
   "(no blocker named)" and "MISSING-CONTRACT (no doc:section named)"): is the blocker issue open and does it really
   own the missing piece; is the named doc section really silent; can the item be written from what the docs DO
   define (then it is FINISHABLE). Output `workstreams/swarm/BLOCKERS-AUDIT.tsv`:
   `issue<TAB>item<TAB>UPHELD|OVERTURNED<TAB>corrected blocker or FINISHABLE<TAB>evidence (quote)`.
3. **Refine issues where needed.** A missing contract that belongs in the documentation: write the precise proposal
   (doc path, section, text) as an issue comment and list it for the owner; never invent it in code. An item whose
   Work text is ambiguous: comment the exact reading with doc quotes. Owner decisions are collected into ONE list in
   this PR's description, not asked one by one.
4. **New work plan without overlaps.** Every FINISHABLE item of the map is planned exactly once. Group the work by
   path family (crate / file set): two lanes never hold the same file at the same time. Order: kernel/ORS/store
   first, blocker issues before the issues they block. Assign by capacity: the Space Bunny lanes get the large
   well-specified FINISHABLE issues in the days they still have; Codex gets the kernel and the hard ones; the verifier
   role moves off Space Bunny before it disappears. Output `workstreams/swarm/PLAN.md` and `PLAN.tsv`:
   `order<TAB>issue<TAB>items<TAB>files (path families)<TAB>lane<TAB>depends_on`.
5. **Stitching and contract plan.** From the map and the code: (a) every MISSING-CONTRACT - doc section, the issue
   that owns it, who writes it, which issues it unblocks; (b) every wiring gap between issues (code with no production
   caller, unreachable crates, components the docs connect but the code does not) - the issue that owns the
   connection, the order. Output `workstreams/swarm/STITCH-PLAN.md`.
6. **Check everything again.** Mechanically: every FINISHABLE item of `BLOCK-MAP.tsv` appears once in `PLAN.tsv`;
   no file family is assigned to two lanes in the same wave; every `depends_on` precedes its dependant; every
   BLOCKED item is either in `STITCH-PLAN.md` or has an open owner issue. Then an independent reviewer (a different
   model) reads PLAN and STITCH-PLAN against the issues. Fix, then merge this PR.
7. **Launch the swarm and start the sprint.** Lanes from `PLAN.tsv` (`v2\SECTORS.json` queues), the lane rules of
   `v2\TEMPLATE-SECTOR.md` (one issue at a time, one branch per lane refreshed from origin/main, one commit and one
   push per issue, BLOCKED instead of inventing, fmt + clippy in lanes, tests by the verifier/root), acceptance by
   `v2\Merge-Daemon-v8.sh`. Hourly report; closures, not PRs, measure progress.

## Done when
- `BLOCKERS-AUDIT.tsv`, `PLAN.md` / `PLAN.tsv`, `STITCH-PLAN.md` are on this branch and pass the step 6 checks;
- the owner decisions list in this PR's description is answered or explicitly deferred;
- this PR is merged and the lanes of the first wave are running.
