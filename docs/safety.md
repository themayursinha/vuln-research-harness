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
and places the script in a new network namespace. Host-level probes remain a
fail-closed preflight; they are not a substitute for a container or microVM
adapter. `vrh verify-sandbox` runs those probes.

## Responsible disclosure

When a candidate survives reproduction, stop at the minimum proof needed to
establish impact. Do not access real user data, persist, pivot, exfiltrate, or
expand scope. Preserve the source digest and evidence, contact the maintainer
through the authorized channel, and wait for remediation before publicizing
technical details.
