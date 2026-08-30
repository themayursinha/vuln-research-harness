# Synthetic path-join lab (local research fixture)

Authorized synthetic target for exercising the VRH campaign loop end-to-end.
No real services, credentials, or client data.

## Layout

```
source/           pinned snapshot input (vrh snapshot)
scripts/          reproduction scripts (host-mounted into the container)
cases.yaml        reproduction cases for vrh repro
campaign.yaml     contract (digest-pinned container image)
Dockerfile        builds localhost/vrh-fixture-lab
```

## Bootstrap

From the repository root:

```bash
make fixture-image
# Copy the printed digest into campaign.yaml environment.container_image

cd campaigns/fixture-lab
../../vrh validate campaign.yaml
../../vrh verify-sandbox .
../../vrh repro cases.yaml .
../../vrh campaign status .
```

`make fixture-image` builds into the same runtime VRH selects via
`container.Detect` (podman, then docker, with preflight checks—not just PATH).
The runtime binary is resolved once; a failed build does not print a stale
digest. Override with `CONTAINER_RUNTIME=docker` or `podman` if both are
installed — that engine is still probed the same way. The committed
`campaign.yaml` already records the digest from fixture creation; rebuild and
update it if you change the Dockerfile.

## What it models

`source/app.py` joins `VRH_SNAPSHOT` with a caller-supplied name without
normalizing `..` segments. `scripts/repro.py` demonstrates reading
`synthetic-secret` via that weak join. The marker `LAB-VULN-MARKER` must
appear when the case reproduces.
