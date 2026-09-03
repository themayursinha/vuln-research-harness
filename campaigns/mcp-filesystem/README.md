# Official filesystem MCP server (local fixture)

Authorized local snapshot of the MCP reference filesystem server
(`modelcontextprotocol/servers` `src/filesystem`, commit
`d73f99efbfd40c3aa1b61e88728b3d49fb52608f`). Synthetic data only. No live
MCP, no real files, no external network.

## Layout

```
source/           pinned snapshot (upstream TS, lockfile, synthetic sandbox/outside)
scripts/          hypothesis probe (host-mounted into the container)
tools.json        sanitized MCP tool schemas from this pin (offline triage)
approaches.yaml   four incompatible families for a bounded worker round
cases.yaml        reproduction cases for vrh repro
campaign.yaml     contract (digest-pinned container image)
Dockerfile        Node runtime for compile + probe
```

## Bootstrap

From the repository root:

```bash
make mcp-filesystem-image
# Copy the printed digest into campaign.yaml environment.container_image

cd campaigns/mcp-filesystem
../../vrh snapshot source .
# Copy the printed digest into campaign.yaml target.source_snapshot

../../vrh validate campaign.yaml
../../vrh verify-sandbox .
../../vrh review-mcp-schema tools.json
../../vrh families seed .
../../vrh round plan . 4
../../vrh campaign status .
../../vrh repro cases.yaml .
```

`make mcp-filesystem-image` uses `cmd/fixture-image` with
`-context campaigns/mcp-filesystem`. Same local-unix-socket rules as
`vrh repro`. Override with `CONTAINER_RUNTIME=docker` or `podman`.

## What it models

The campaign success condition is reading `outside/secret.txt` through the
server's `validatePath` while the allowed root is `sandbox/`. The probe
calls that upstream function; it prints `MCPFS-ROOT-ESCAPE` only if the
synthetic secret is returned. A non-reproduction means confinement held on
this pin. That is a baseline, not a finding.

## Bounded four-worker round

`approaches.yaml` registers four incompatible mechanisms (parent segments,
symlink escape, prefix matching, Unicode NFC equivalents). `vrh families seed .`
writes them to the ledger; `vrh round plan . 4` publishes one inbox request
per family. Workers (human or isolated agent) write result envelopes into
`inbox/results/`. Do not invent results: model prose is never evidence.

`tools.json` is a sanitized copy of this pin's tool schemas for
`vrh review-mcp-schema`. Hypotheses are triage, not findings.

## License

Upstream sources and `source/LICENSE` remain under the MCP project's
MIT / Apache-2.0 terms. Synthetic fixture files are part of this repository.
