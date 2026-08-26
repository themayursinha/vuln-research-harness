# vuln-research-harness (VRH)

A deterministic campaign harness for AI-assisted vulnerability research on
**authorized, locally reproducible targets**.

VRH turns the multi-agent research pattern demonstrated by OpenAI's Cycle
Double Cover prompt (adapted to security research by Searchlight Cyber's
wp2shell work) into a stateful, auditable system: a campaign contract that
pins the target and success condition, an approach registry that prevents
premature agent convergence, and an evidence ledger that records every state
transition from hypothesis to reproduced impact.

**Status: foundation + controlled execution + validation lane.** The campaign
contract, approach registry, evidence ledger, snapshot manifest, capability
gate, manual inbox round loop, reproduction runner, container adapter
(digest-pinned local image, `--network=none`, read-only snapshot mount),
sandbox probes, and adversarial validator are implemented and tested. An
automated agent runner and a microVM adapter are not built yet.
See [docs/roadmap.md](docs/roadmap.md) and [docs/campaigns.md](docs/campaigns.md).

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

See [docs/safety.md](docs/safety.md) and [docs/campaigns.md](docs/campaigns.md). Running VRH against systems you do not
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

# Pin the target source snapshot (manifest + normalized archive)
vrh snapshot /path/to/target ./campaigns/mcp-filesystem-server

# Manage approach families
vrh families add ./campaigns/mcp-filesystem-server parser "validation ordering"
vrh families list ./campaigns/mcp-filesystem-server

# Run a bounded round: publish request envelopes, execute externally in
# isolation, then ingest validated results
vrh round plan ./campaigns/mcp-filesystem-server 4
vrh round ingest ./campaigns/mcp-filesystem-server
```

## Repository layout

```
cmd/vrh/            CLI entry point (init, validate, snapshot, families, round, repro, adversarial, verify-sandbox)
internal/contract/  campaign contract load/validate (YAML, digest-pinned)
internal/registry/  approach family registry (convergence + blocked-path state)
internal/ledger/    append-only evidence ledger (JSONL, hash-linked)
internal/manifest/  digest-pinned source snapshot (manifest + normalized archive)
internal/capability/ executor capability gate (fail-closed admission)
internal/worker/    structured request/result schema for research lanes
internal/coordinator/ round state machine (plan + ingest)
internal/executor/  manual inbox executor (v1; no target execution)
internal/repro/     minimal reproduction runner (marker + pinned snapshot)
internal/container/ disposable OCI adapter (digest-pinned image, network none)
internal/sandbox/   network-denial probes (fail-closed)
internal/validate/  adversarial disproof lane
docs/               method, safety model, contract reference, campaign layout, roadmap
```

## License

MIT. See [LICENSE](LICENSE).

## Validation lane

```bash
# Prove the pinned local image cannot reach the network, then run cases
vrh verify-sandbox ./campaigns/mcp-filesystem-server
vrh repro cases.yaml ./campaigns/mcp-filesystem-server

# Record an adversarial validation verdict for a finding
vrh adversarial F1-json-bypass attempts.json "finding stands"
```

`vrh repro` fails closed: it runs the same admission gate as `round plan`
(contract, manifest digest, source-tree verify), requires a digest-pinned
**local** container image (`environment.container_image`), and runs each
case inside podman/docker with `--network=none`, `--pull=never`, a
read-only rootfs, and a read-only snapshot mount. Remote Docker/Podman
endpoints are refused. Host `venv_python` paths
are refused; the image must provide the interpreter. Process-local
namespaces remain the unit-test sandbox, not the CLI execution boundary.
