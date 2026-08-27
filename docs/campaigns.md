# Campaign layout

A campaign directory is created by `vrh init` and extended by the round
commands:

```
campaigns/<name>/
  campaign.yaml      contract (validated by vrh validate)
  manifest.json      pinned source snapshot (vrh snapshot)
  source.tar.gz      normalized snapshot archive
  registry.json      approach families (vrh families ...)
  state.json         coordinator round state
  ledger.jsonl       hash-linked evidence ledger
  inbox/
    requests/        one JSON envelope per dispatched request
    results/         one JSON envelope per worker result
```

## Flow

```bash
vrh init campaigns/<name>
# edit campaign.yaml: real target, authorization record, impact, evidence
vrh validate campaigns/<name>/campaign.yaml
vrh snapshot /path/to/target/source campaigns/<name>
# paste the printed digest into campaign.yaml target.source_snapshot

vrh families add campaigns/<name> parser "request validation ordering"
vrh families add campaigns/<name> auth   "identity confusion"
vrh families add campaigns/<name> cache  "cache poisoning"

vrh round plan campaigns/<name> 3      # publishes request envelopes
# workers execute in their own isolation; each returns a result envelope
# with capability claims into inbox/results/
vrh round ingest campaigns/<name>      # verifies gate + schema, updates registry

vrh verify-sandbox campaigns/<name>    # prove the pinned image runs with network=none
vrh repro cases.yaml campaigns/<name>  # admission + container isolation, then run cases
vrh adversarial F1 attempts.json "finding stands"
```

`round plan`, `round ingest`, and `vrh repro` all run the **admission gate** first: the
contract must load and validate, the campaign `source_snapshot` must equal
the manifest digest, and the source tree must still verify against the
manifest — including a check that no file was added or removed since the
snapshot. A directory with families but no valid authorized contract never
dispatches work. `vrh repro` additionally extracts a fresh copy of the pinned
archive for each case and runs the script in a digest-pinned local
container (`--network=none`, read-only snapshot mount, `--pull=never`).
It refuses to execute unless the image is already local and a created
container inspects as `--network=none`, read-only, cap-drop ALL, and
no published ports. Process-local namespaces are used only in unit tests.

The append-only ledger is the **single source of truth**; `registry.json`
and `state.json` are materialized views reconstructed from it. Every command
reconciles before acting, so a crash at any point — including a lost
`registry.json` — cannot strand a campaign or lose a blocked/attempt state.
`round plan` records its family set durably before publishing anything, so a
retry after a crash publishes the exact original set rather than recomputing
from inflated attempt counts. Ingested result envelopes move to
`inbox/results/consumed/` (keyed by the request ID inside the envelope, not
the filename), so a stale blocked result can never re-block a reopened
family.

## Result envelopes

Workers (human or agent) answer a request by writing an envelope into
`inbox/results/`:

```json
{
  "capabilities": [
    {"name": "no_external_network", "satisfied": true, "evidence": "unshare -n"},
    {"name": "no_real_credentials", "satisfied": true, "evidence": "synthetic fixtures"},
    {"name": "disposable_environment", "satisfied": true, "evidence": "tmpfs container"},
    {"name": "read_only_source_mount", "satisfied": true, "evidence": "mount -o ro"}
  ],
  "result": {
    "request_id": "parser--r1",
    "status": "blocked",
    "summary": "validation ordering pinned down",
    "block_reason": "no mismatch reachable pre-auth"
  }
}
```

`vrh round ingest` rejects the whole batch if any envelope fails the
capability gate or the result schema. Statuses: `progress`, `blocked`,
`finding`, `refuted`. Findings must carry evidence paths; blocked results
must carry a reason. A result must answer the exact ID of an outstanding
request; invented IDs and prefix-based family guesses are rejected.
