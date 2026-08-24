# vuln-research-harness (VRH)

A deterministic campaign harness for AI-assisted vulnerability research on
**authorized, locally reproducible targets**.

VRH turns the multi-agent research pattern demonstrated by OpenAI's Cycle
Double Cover prompt (adapted to security research by Searchlight Cyber's
wp2shell work) into a stateful, auditable system: a campaign contract that
pins the target and success condition, an approach registry that prevents
premature agent convergence, and an evidence ledger that records every state
transition from hypothesis to reproduced impact.

**Status: scaffold.** The campaign contract, approach registry, and evidence
ledger are implemented and tested. The agent runner, adversarial validator,
and sandbox integration are not built yet. See [docs/roadmap.md](docs/roadmap.md).

## Why

Frontier-model vulnerability research works when it is treated as a search
problem, not a chat:

- **Success is defined before the search starts** — target, starting
  privilege, deployment reality, impact, and the concrete artifact that
  proves it.
- **Diverse approaches stay alive** — agents are grouped by research idea,
  converged families are split, exhausted paths are marked blocked, and
  blocked paths reopen only on a materially new mechanism.
- **Every claim is validated adversarially** — a finding is not a finding
  until an independent agent fails to disprove it and a minimal reproduction
  runs from a clean source snapshot.
- **The full chain matters** — isolated primitives are not impact. The
  campaign ends at the defined success condition or with an explicit,
  evidenced closure.

The harness encodes those rules as data and state transitions, so a campaign
can be paused, audited, measured (cost, runtime, false positives), and
reproduced by someone else.

## Safety model (non-negotiable)

VRH is for **authorized research only**. The campaign contract carries an
explicit authorization record, and campaigns are designed to run against
local snapshots in isolated environments:

- local source snapshot pinned by digest, no `.git` history during discovery;
- network-denied or allowlisted sandbox execution;
- synthetic secrets and synthetic success markers, never real credentials
  or real user data;
- discovery phase is source-first: no changelog diffing, no public writeup
  harvesting for the specific target;
- validation and disclosure phases may consult history, advisories, and
  public research.

See [docs/safety.md](docs/safety.md). Running VRH against systems you do not
own or lack explicit written permission to test is out of scope and
unsupported.

## Install

```bash
go install github.com/themayursinha/vuln-research-harness/cmd/vrh@latest
```

## Usage

```bash
# Create a campaign contract from the template
vrh init ./campaigns/mcp-filesystem-server

# Validate the contract (fails on missing authorization, unsafe sandbox
# settings, or an undefined success condition)
vrh validate ./campaigns/mcp-filesystem-server/campaign.yaml

# (roadmap) run the campaign, resume it, export the evidence ledger
# vrh run ./campaigns/mcp-filesystem-server/campaign.yaml
# vrh ledger export ./campaigns/mcp-filesystem-server/
```

## Repository layout

```
cmd/vrh/            CLI entry point
internal/contract/  campaign contract load/validate (YAML, digest-pinned)
internal/registry/  approach family registry (convergence + blocked-path state)
internal/ledger/    append-only evidence ledger (JSONL, hash-linked)
docs/               method, safety model, contract reference, roadmap
```

## License

MIT. See [LICENSE](LICENSE).
