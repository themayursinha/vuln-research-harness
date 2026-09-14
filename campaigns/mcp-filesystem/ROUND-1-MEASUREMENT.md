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
| dotdot  | parent-directory segments through validatePath | refuted | 1029 ms | `c3094750…febd8` |
| prefix  | allowed-directory string-prefix matching      | refuted |  896 ms | `44c5ec08…da35c` |
| symlink | symlink inside root resolving outside         | refuted |  939 ms | `9e7d33ec…3561`  |
| unicode | Unicode NFC-equivalent path components        | refuted |  878 ms | `8dc217e3…7b23b` |
| —       | success-condition probe (root-escape-probe)   | not reproduced | 943 ms | `2dba5dbc…aa35` |

Full digests: `evidence/*/repro_outcomes.json` (per family) and
`repro_outcomes.json` (baseline). Ledger: 22 events, hash-linked
(`ledger.jsonl`, local-only per .gitignore policy).

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

## Calibration control (Kaiser discipline 4)

`campaigns/fixture-lab` — known planted path-join bug F-LAB-001 —
**REPRODUCED** in the same locked lane (marker `LAB-VULN-MARKER`, output
digest `0945b1cfb8c63508fe6d1f34e6ffb2317125eacd6b7f26ee1389d5a9e78586ec`).
The detection pipeline demonstrably catches a real bug, so the four
non-reproductions above are meaningful evidence of confinement, not a dead
probe.

## Measured dimensions (roadmap Phase 4)

- **Approach diversity**: 4/4 dispatched lanes used incompatible mechanisms
  (lexical containment, realpath containment, separator-prefix matching,
  NFC-equivalence walk) targeting four distinct source regions
  (path-validation.ts:11-86, lib.ts:77-97, lib.ts:160-168, lib.ts:100-138).
  No convergence: zero families converged on the same code path or hypothesis.
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
