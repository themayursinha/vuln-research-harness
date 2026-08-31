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

`make fixture-image` runs `cmd/fixture-image`: same `container.Detect`
preflight as `vrh repro`, the sanitized local client environment (no
`DOCKER_CONTEXT` / remote hosts), and a digest pin even when Docker has
not populated `RepoDigests` (local build image ID is a valid `sha256:…`
pin). Override with `CONTAINER_RUNTIME=docker` or `podman`. Copy the
printed pin into `campaign.yaml` `environment.container_image`.

## What it models

`source/app.py` joins `VRH_SNAPSHOT` with a caller-supplied name without
normalizing `..` segments. `scripts/repro.py` demonstrates reading
`synthetic-secret` via that weak join. The marker `LAB-VULN-MARKER` must
appear when the case reproduces.
