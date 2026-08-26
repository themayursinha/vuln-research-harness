# Safety model

VRH is an authorized research harness. It is not a scanner for arbitrary
internet targets and it does not grant permission to test a system.

## Required boundaries

- Written permission and an explicit scope are required before a campaign can
  validate.
- The target is a locally owned or explicitly authorized source snapshot.
- The deployment is disposable and isolated.
- The network is denied by default or restricted to an explicit allowlist.
- Test data, credentials, and success markers are synthetic.
- Discovery does not use public sources to copy a known solution or patched
  diff.
- Validation may use advisories and history after a candidate exists.

## Non-goals of the current scaffold

The current code does not execute agents or create microVMs. A valid
contract is an admission check, not a substitute for the container runtime.

`vrh repro` extracts a fresh copy of the pinned archive for each case and
runs the script inside a local podman or docker container: `--network=none`,
`--pull=never`, `--read-only` rootfs, `--cap-drop=ALL`, no-new-privileges,
memory and pids limits, no published ports, snapshot and script bind-mounted
read-only, scratch on tmpfs. The campaign must pin
`environment.container_image` by digest, and that image must already exist
locally. Remote Docker/Podman endpoints and contexts are refused; the
runtime must be a local unix socket. Containers are named so a deadline
cannot leave a running research box. Loopback remains available for local
fixtures.
Process-local user namespaces and Landlock are the unit-test sandbox; they
are not the CLI execution boundary. `vrh verify-sandbox <campaign-dir>`
proves the runtime applied those flags before a run.

## Responsible disclosure

When a candidate survives reproduction, stop at the minimum proof needed to
establish impact. Do not access real user data, persist, pivot, exfiltrate, or
expand scope. Preserve the source digest and evidence, contact the maintainer
through the authorized channel, and wait for remediation before publicizing
technical details.
