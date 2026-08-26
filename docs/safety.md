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

The current code does not execute agents, create containers, or enforce
filesystem limits. Those are future integrations and must not be implied by
a valid contract. A valid contract is an admission check, not a sandbox.

`vrh repro` executes each case against a fresh extract of the pinned archive
inside a new user+network namespace. Landlock allows writes only under a
scratch directory, so chmod inside the user namespace cannot turn the
extract into a writable tree. The runner tries to bring loopback up for
local TCP/UDP fixtures; kernels with `apparmor_restrict_unprivileged_userns`
may deny that ioctl (bind to 127.0.0.1 still works; connect may not).
Outbound interfaces are absent. The script sees a stripped environment and
a process-group deadline. The marker counts only on a successful (exit 0)
stdout hit. Host-level probes remain a fail-closed preflight; they are not
a substitute for a container or microVM adapter. `vrh verify-sandbox` runs
those probes.

## Responsible disclosure

When a candidate survives reproduction, stop at the minimum proof needed to
establish impact. Do not access real user data, persist, pivot, exfiltrate, or
expand scope. Preserve the source digest and evidence, contact the maintainer
through the authorized channel, and wait for remediation before publicizing
technical details.
