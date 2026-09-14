# Round 1 measurement — bounded four-worker pilot on mcp-filesystem

Executed 2026-09-14 on stellaris against
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
| prefix  | allowed-directory string-prefix matching      | refuted |  956 ms | `44c5ec08…da35c` |
| symlink | symlink inside root resolving outside         | refuted |  947 ms | `9e7d33ec…3561`  |
| unicode | Unicode NFC-equivalent path components        | refuted | 1001 ms | `8f464719…4632`  |
| —       | success-condition probe (root-escape-probe)   | not reproduced | 943 ms | `2dba5dbc…aa35` |

Full digests: `evidence/*/repro_outcomes.json` (per family) and
`repro_outcomes.json` (baseline). Ledger: 19 events, hash-linked
(`ledger.jsonl`, local-only per .gitignore policy).

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
  attacker input on this pin.

## Safety

No live infrastructure, no external network (locked lane network=none),
synthetic data only, capability gate fail-closed (all four claims verified
per envelope), contract checks untouched. Families remain active: a refuted
mechanism is not an exhausted family; reopening requires a materially new
mechanism (anti-whack-a-mole rule).
