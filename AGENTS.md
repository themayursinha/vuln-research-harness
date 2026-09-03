# vuln-research-harness

## Purpose

A deterministic campaign harness for AI-assisted vulnerability research on
authorized, locally reproducible targets: campaign contract, approach
registry, evidence ledger. It encodes multi-agent search discipline as data
and state transitions.

This repo is a research client, not an enforcement proxy. Do not merge those
concerns.

## Hard rules (need Mayur)

- Public repo: nothing private ever lands here. No Obsidian paths, no
  internal hostnames, no client names, no real target names from work.
- No agent execution against live infrastructure. Campaigns target local
  snapshots in network-denied sandboxes only.
- No fabricated evidence. Every ledger entry must come from an executed
  command or a cited source. Model prose is never evidence.
- Do not weaken safety checks in `internal/contract` to make campaigns pass.
- Do not add dependencies without Mayur.

## Verify

```bash
export PATH=/usr/local/go/bin:$PATH   # if go is not on PATH
make check   # vet + test + build
```

## Conventions

- Boring Go, stdlib first. Only dependency so far: gopkg.in/yaml.v3.
- Tests next to code, table-driven where it helps.
- The evidence ledger is append-only JSONL and hash-linked.
