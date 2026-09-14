# Round 1 measurement — bounded four-worker pilot on mcp-filesystem

Executed 2026-09-14 on a private Linux execution host against
`localhost/vrh-mcp-filesystem@sha256:5033003e549ab2dd170607f70856730ade6d5405a733a32c397e91dd57ec14db`
(digest-pinned, network=none, read-only snapshot, caps dropped, no pull).
Executor: manual inbox executor v1 — the four worker lanes were executed by
an AI agent session under the same locked lane; every claim below traces to a
ledger event or an exported outcome. No worker result was fabricated.

## Outcome

Round 1 dispatched four incompatible families and ingested 4/4 structured
results. **Zero confirmed findings, zero suspected findings.** Confinement
held on this pin. That is the measured result, not a failure of the round:
the campaign's success condition (read `outside/secret.txt` through the tool
gate) was probed four ways and did not reproduce.

| family  | mechanism                                   | status   | probe duration | output digest (sha256) |
|---------|---------------------------------------------|----------|----------------|------------------------|
| dotdot  | parent-directory segments through validatePath | refuted |  976 ms | `e2e29f8e…51680` |
| prefix  | allowed-directory string-prefix matching      | refuted |  925 ms | `44c5ec08…da35c` |
| symlink | symlink inside root resolving outside         | refuted |  885 ms | `9e7d33ec…3561`  |
| unicode | Unicode NFC-equivalent path components        | refuted |  935 ms | `ec0da4d9…76de0` |
| —       | success-condition probe (root-escape-probe)   | not reproduced | 893 ms | `2dba5dbc…aa35` |

Durations are from the final committed probe scripts (after the
post-review corrections below); output digests were stable across every
re-execution of each lane.

Full digests: `evidence/*/repro_outcomes.json` (per family) and
`repro_outcomes.json` (baseline). Ledger: 31 events, hash-linked
(`ledger.jsonl`, local-only per .gitignore policy; the count includes the
append-only correction re-executions documented below).

## Post-review corrections (2026-09-14, same day)

An adversarial code review (Codex, GPT 5.6 Sol, high effort) of this patch
found five defects; all were fixed and the affected lanes re-executed in the
same locked lane. Corrections are append-only: the ledger carries both the
original and the corrected runs.

1. **Internal hostname in this note** (P1) — removed; the repo forbids
   internal hostnames in public artifacts.
2. **Unicode escape oracle was dead** (P1) — the original escape tree never
   created the outside secret, so a hypothetical escape could not have
   emitted the marker; a "did not reproduce" would have been unfalsifiable.
   Corrected probe creates a readable outside secret.
3. **Unicode lane never reached the NFC fallback** (P1) — both sub-tests
   byte-matched an on-disk entry, so `fs.realpath` succeeded directly and
   `resolveUnicodeEquivalentPath` was never exercised. Corrected probe uses
   U+01ED (ǭ), which has three byte-distinct canonically-equivalent
   spellings: the compat case requests a byte-absent decomposed form over a
   composed-only entry (fallback must resolve it inside the root), the
   ambiguity case requests the mark-reordered spelling over two on-disk
   equivalents (guard must fire), and the encoding preconditions are
   asserted at startup. Outcome unchanged: non-reproduction, new digest
   `48a96f646b8ba99eaf3ffc977627cc947d4031fb161ba85f54fb33dba3b2f2b2`
   (original `8f464719…4632` is superseded).
4. **Campaign-root baseline outcome was ignored by .gitignore** (P2) — the
   success-condition `repro_outcomes.json` is now whitelisted and committed
   so the referenced digest is inspectable from a fresh checkout.
5. **Positive controls did not fail closed** (P2) — prefix and symlink
   probes now fail the run via the runner's sandbox-fail exit (125) if an
   in-root positive control is unexpectedly rejected: `vrh repro` errors
   out, exports nothing, and appends no ledger event, so a misconfigured
   probe can never be recorded as a valid non-reproduction. (An ordinary
   nonzero exit would not suffice — the runner records those as ordinary
   `vulnerable:false` outcomes.) Re-runs of both lanes produced
   byte-identical output digests to the originals, confirming the originals
   were healthy runs.

A re-review after those fixes (same reviewer) found one residual P1, fixed
in the same append-only manner:

6. **Escape tree did not exercise the per-step containment check** — the
   original escape attempts were lexically collapsed by `path.resolve` to
   in-root paths, or rejected by the lexical gate before the NFC walk, so
   the lane would have passed even with the walk's per-step realpath
   containment re-check (lib.ts:131-133) removed. Corrected escape tree:
   an in-root entry named with one byte-distinct NFC spelling of U+01ED
   symlinks to the readable outside directory, and the request uses a
   different, byte-absent spelling — `fs.realpath` on the full request
   ENOENTs, so only the walk's equivalent-match step can resolve it, and
   the per-step check must reject it. Falsifiability is by construction:
   with the check removed, the walk resolves the outside secret and the
   marker fires. Outcome unchanged: non-reproduction, new digest
   `8dc217e3702ba47f536633bd0e6bf706975de597af8e6e339d70c76589b7b23b`
   (supersedes `48a96f64…2f2b2` and the original `8f464719…4632`).

A second re-review pass found two more defects, also fixed:

7. **Invalid-probe exit channel** (P1) — the fail-closed exits introduced
   in fix 5 used a plain nonzero exit code, but the repro runner records
   every nonzero exit except 125 as an ordinary `vulnerable:false`
   outcome; an invalid probe would still have been ledgered as a
   non-reproduction. All three probes now use the runner's sandbox-fail
   exit (125): the run errors out, exports nothing, and appends no ledger
   event. All three lanes re-executed; digests unchanged.
8. **Coverage artifact overclaimed two pre-gate surfaces** (P2) —
   `expandHome` (path-utils.ts:119-124, citation was wrong) and the
   Windows drive-path rejection (lib.ts:145-147) run before the shared
   lexical gate, so no round-1 attempt exercised them; both are now
   `pending` round-2 candidates instead of `covered-gate`.

A third re-review pass found three more, also fixed:

9. **Prerequisite failures still used ordinary exits** (P1) — the
   fail-closed channel introduced in fix 7 covered only the explicit
   positive-control checks; a tsc compile failure (exit 2), a missing
   environment variable, or any uncaught exception in a probe would still
   have been ledgered as an ordinary non-reproduction. All four probes and
   the baseline `scripts/repro.mjs` now install uncaughtException /
   unhandledRejection handlers and route every prerequisite failure
   through exit 125. All lanes and the baseline re-executed; every output
   digest unchanged, confirming healthy runs.
10. **Stale durations in this table** (P2) — the table now reports the
    durations from the final exported outcomes of the last re-execution.
11. **Diversity overstatement** (P2) — the diversity bullet now reports
    four distinct attack shapes across three distinct source regions and
    explicitly counts the dotdot/prefix convergence on the shared lexical
    containment gate, instead of claiming four disjoint source regions.

A fourth re-review pass (same reviewer) found three more, also fixed:

12. **Internal board identifier in coverage.yaml** (P1) — removed; the
    public-data rule covers any internal identifier, not just hostnames.
13. **Marker could fire without an observed impact** (P1) — the escape
    tree emitted the marker when validatePath returned any outside path,
    even if the subsequent read failed; the campaign's success condition
    is *reading* the synthetic secret. The marker now fires only after the
    read returns content containing the secret; any outside resolution
    without a readable secret fails the probe (exit 125), and the compat
    tree treats an outside resolution as invalid for the same reason.
    Outcome unchanged: non-reproduction, new digest
    `ec0da4d89dc6f4276da8f64ccae899588de782cd0d75aeea5bcaa4eefd876de0`.
14. **dotdot lane lacked a positive control** (P2) — a compiled validator
    that rejected everything would have produced a quiet exit and been
    recorded as a refutation. The lane now validates and reads an in-root
    fixture file first and fails the run (exit 125) if that control
    fails. Outcome unchanged: non-reproduction, new digest
    `e2e29f8ef720beabe7b12b1b0a5d04fbf6934f9c5784e94dcb8f9f627fa51680`
    (supersedes `c3094750…febd8`).

## Calibration control (Kaiser discipline 4)

`campaigns/fixture-lab` — known planted path-join bug F-LAB-001 —
**REPRODUCED** in the same locked lane (marker `LAB-VULN-MARKER`, output
digest `0945b1cfb8c63508fe6d1f34e6ffb2317125eacd6b7f26ee1389d5a9e78586ec`).
The detection pipeline demonstrably catches a real bug, so the four
non-reproductions above are meaningful evidence of confinement, not a dead
probe.

## Measured dimensions (roadmap Phase 4)

- **Approach diversity**: 4/4 dispatched lanes used incompatible attack
  shapes (parent-segment traversal, separator-prefix siblings, symlink
  resolution, NFC-equivalent spelling) across three distinct source regions
  (path-validation.ts:11-86, lib.ts:77-97, lib.ts:160-168, lib.ts:100-138).
  Convergence accounting: dotdot and prefix both terminate at the shared
  lexical containment gate (`isPathWithinAllowedDirectories`,
  path-validation.ts:84) — two shapes, one gate — while symlink and unicode
  exercise distinct later guards (realpath containment, NFC walk). Zero
  families converged on the same hypothesis.
- **False positives**: 0. No lane reported a finding; no candidate entered
  the adversarial lane (0 validation_verdict events). Nothing was refuted by
  validation because nothing was claimed beyond its artifact — the crash-first
  rule kept every claim at "refuted mechanism" level.
- **Evidence completeness**: 4/4 results carry (a) source paths with line
  references, (b) a deterministic committed probe, (c) an exported outcome
  with exit code, duration, and output digest, (d) the ledger's hash-linked
  result_ingested event. The schema reviewer added 31 triage hypotheses
  (evidence/schema-triage.txt) — triage only, none escalated (correct: they
  are surface descriptors, not defects).
- **Runtime**: wall clock dispatch→ingest 18:23:20→18:35:34 CEST ≈ 12.2 min,
  of which in-container probe execution was 4×~1 s + 0.9 s baseline; the
  remainder was source-first analysis and probe authoring by the manual
  executor. Container-time cost per lane ≈ 1 s (tsc compile dominates).
- **Model cost**: not metered by the harness (manual executor v1 has no
  token accounting). Recorded qualitatively: one agent session, 4 lanes,
  ~40 min session wall time including analysis. A metered agent runner
  (roadmap Phase 5) is required before model cost becomes a comparable metric.

## Source-level results (why confinement held)

- dotdot: relative paths resolve against the allowed root, then the lexical
  gate requires `startsWith(normalizedDir + path.sep)` (path-validation.ts:84)
  — all parent-segment variants rejected before any file access.
- prefix: the separator-append defeats text-prefix sibling paths
  (`/root/sandboxevil`, `/root/sandbox.evil` rejected; equal-path and in-root
  boundaries pass).
- symlink: realpath containment (lib.ts:160-168) rejects escaping symlinks
  while keeping in-root symlinks usable; the precondition is also
  unestablishable via the tool surface (no symlink primitive in tools.json).
- unicode: the NFC walk (lib.ts:100-138) is reachable only for lexically
  inside ENOENT paths, starts at the realpath'd allowed root, and re-verifies
  containment per step; `outside` is ASCII with no NFC alias. The dead branch
  at lib.ts:105-107 (returning an uncontained path) is unreachable for
  attacker input on this pin. Verified with byte-absent equivalent spellings
  of U+01ED (three canonical encodings): the fallback resolved the decomposed
  request to the composed entry inside the root, the reordered request raised
  the ambiguity error, and an NFC-equivalent symlinked entry resolving
  outside the root was rejected by the walk's per-step realpath containment
  check (lib.ts:131-133) — the exact check the escape tree is built to
  exercise, with a marker-oracle that fires if that check is removed.

## Safety

No live infrastructure, no external network (locked lane network=none),
synthetic data only, capability gate fail-closed (all four claims verified
per envelope), contract checks untouched. Families remain active: a refuted
mechanism is not an exhausted family; reopening requires a materially new
mechanism (anti-whack-a-mole rule).
