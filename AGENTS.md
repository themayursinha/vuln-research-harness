# vuln-research-harness

## Purpose

A deterministic campaign harness for AI-assisted vulnerability research on
authorized, locally reproducible targets: campaign contract, approach
registry, evidence ledger. It encodes the multi-agent search discipline from
the OpenAI CDC prompt (as adapted for security research by Searchlight
Cyber's wp2shell work) as data and state transitions.

This repo is separate from mcp-visor by design. Visor is the enforcement
proxy; VRH is a research client that could sit behind an enforcement boundary
later. Do not merge concerns.

## Hard rules (need Mayur)

- Public repo: nothing private ever lands here. No Obsidian paths, no
  internal hostnames, no client names, no real target names from work.
- No agent execution against live infrastructure. Campaigns target local
  snapshots in network-denied sandboxes only.
- No fabricated evidence. Every ledger entry must come from an executed
  command or a cited source. Model prose is never evidence.
- Do not weaken safety checks in `internal/contract` to make campaigns pass.
- Do not add dependencies without Mayur.

## Model routing

Follow the standard loop: GPT-5.6-sol architect, Grok 4.6 High builder,
DeepSeek V4 Pro reviewer (see the `three-model-harness-loop` skill). This is
a small repo; keep design contracts short and skip the loop only for typos.

## Verify

```bash
export PATH=/usr/local/go/bin:$PATH   # if go is not on PATH
make check   # vet + test + build
```

## Conventions

- Boring Go, stdlib first. Only dependency so far: gopkg.in/yaml.v3.
- Tests next to code, table-driven where it helps.
- The evidence ledger is append-only JSONL, hash-linked, modeled on the
  mcp-visor audit log but independent of it.
