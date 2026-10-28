# JavaScript source selector verification — 2026-10-24

PR #5048 extends the existing static source selection contract with folder
prefixes and segment globs. Exact inventoried paths keep precedence, including
literal wildcard characters. Matching is case-sensitive, preserves the caller's
request and first-occurrence priority, and never executes target JavaScript.
The result exposes resolved `selected_paths` only for expanded selections.

## Ownership corrections

Baseline `0c273357e5ff75d4e053e38a043f29243c3e5f1b` integrates the contributor's
original head with main `21a20306b4887ff8e6b614b6ae34a387cfbdf1d8`.
Candidate `81ea5288ade45836d27312f81906d299958d58a8` removes recursive whole-path
matching and failed-state string sets. It compiles a selector once, collapses
adjacent double-star segments, splits inventory paths once when glob matching
is needed, and sorts once per request. Exact-only requests do not allocate
sorted or segmented path lists. Segment matching still uses Unicode code
points for `?`; aliases and case are not normalized.

The resolver also owns whether an unmatched nonempty selector needs complete
inventory to establish absence. The artifact consumer uses that fact instead
of separately interpreting raw selectors. Unknown traversal returns a typed
unavailable result with the retained inventory. Observed matches remain useful
with partial application coverage; no unseen files are inferred absent. The
old consumer-side suffix/lookup guard is removed; lower-bound lookup remains
for its distinct inventory-observation consumer.

Two 200,000-segment selectors (about 600 KB each, ending in a matching or
missing file) throw `RangeError` before the correction and resolve afterward.
The initial 20,000-segment controls passed in the Vitest worker; they did not
reproduce stack overflow. These capacity failures are not counted as completed
performance tasks or speedups.

Two real permission controls fail before correction: `private/**` and
`private` under an unreadable directory return invalid-selection errors. The
existing wildcard ending in `.js` control and three positive coverage controls
pass. After correction, **25 source/real-filesystem checks pass**, including
four nonadjacent-star backtracking/Unicode cases and readable folder matches
with retained incomplete-inventory limitations. These permission checks run as
a non-root Linux user and restore access during cleanup. The first boundary
attempt lacked built analysis workers; its worker crashes were setup failures,
not feature defects. The definitive comparison builds both trees first.

## Public workflows and gates

All **21 public workflow checks pass** through compiled CLI and production
stdio MCP, including directory/ASAR selectors, both CLI routes, JSON-file
selectors combined with the existing #5029 input path, exact-only output,
ordering, invalid-input correction, unavailable bytes, retained identity and
schema validation. Together with the source/filesystem selection, **46 checks
pass**. The compiled workflow selection takes 191.073 s elapsed, 201.028 s
waited CPU and 1153.8 MiB sampled family RSS. Final source checks take 9.850 s,
10.123 s CPU and 744.2 MiB sampled family RSS. `check:fast`, complete
`format:check` and `docs:check` pass after the final source/documentation edits.
The original contributor reported Windows 11 validation; it was not rerun here.
No Hopper, Ghidra, browser target, device or target code was launched.

## Completed-task costs

Twelve completed, alternating CLI tasks compare the pinned baseline/candidate:
three pairs each for a normal folder and a legal capacity case with 64
overlapping selectors containing 512 adjacent double-star segments apiece.
Each task analyzes the same 128 generated static JavaScript modules in a
directory. The one unselected package manifest keeps application coverage
partial without truncation; all 128 selected modules parse successfully and
their exact text-byte total is checked. Every complete Evidence field and ID
agrees between versions for each case.

| CLI task                 | Estimated stdout + invocation tokens, before → after | Elapsed median s | Waited CPU median s | Sampled family RSS median MiB |
| ------------------------ | ---------------------------------------------------: | ---------------: | ------------------: | ----------------------------: |
| One folder selector      |                                    574,036 → 574,036 |  24.265 → 26.447 |     21.346 → 22.851 |                 556.5 → 547.4 |
| 64 overlapping selectors |                                    672,849 → 672,849 |  31.241 → 23.730 |     22.357 → 18.630 |                 560.5 → 561.6 |

Normal elapsed ranges are 19.374–24.800 / 21.862–28.999 s and CPU
15.569–23.982 / 15.046–23.966 s. Capacity-case ranges are 21.309–31.432 /
20.451–25.884 s elapsed and 17.601–23.676 / 16.559–23.831 s CPU. These
ranges overlap; normal medians are higher after the change. RSS ranges are
555.0–560.2 / 541.2–553.8 MiB for the normal task and 555.0–578.8 /
556.5–583.3 MiB for capacity. No general latency, CPU or memory improvement is
established. The capacity case is not representative of ordinary query latency.

Token counts are tokenx 1.3.0 estimates over the full CLI stdout and known
invocation, not billed model usage. CLI and analysis-worker processes are
fresh; OS/module/file caches are warm. Cold-disk behavior is not isolated.
Input-file creation, discovery, prompts, schemas/catalog, client parsing and
MCP transport costs are unmeasured and excluded. The normal selector JSON is
7 bytes, SHA-256 `8a5ddc82a12b33bd1f871e54d98212e1e63dc8150e183c40b0c2d6086f41cd8c`;
the capacity input is 98,816 bytes, SHA-256
`72e1eecefbbc80d691a6ea1da92be776526fde215dabf91461642bc488679779`.
Caller inputs are retained rather than silently simplified for cheaper output.

Runtime measurements use Node 24.22.1, npm 11.16.0, two-CPU affinity and a
2 GiB Node old-space setting. Recursive process-family RSS is sampled every
50 ms; shared pages can be counted more than once and short-lived descendants
can be missed. CPU is accounted from waited children; these are local
observations with substantial environmental variation, not resource guarantees.
