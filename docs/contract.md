# Campaign contract reference

The contract is YAML. `vrh validate` rejects missing or unsafe fields.

```yaml
version: v1
name: campaign-name

target:
  name: authorized-target
  source_snapshot: sha256:...
  source_path: ./target

authorization:
  owner: organization-or-researcher
  scope: local snapshot only
  written_permission: true
  evidence: permission-record-reference

attacker:
  starting_privilege: unauthenticated
  capabilities:
    - send protocol requests to local fixture
  excluded:
    - real credentials
    - real user data
    - external network

environment:
  deployment: disposable local container
  network: denied
  isolation: rootless container with read-only source mount
  container_image: localhost/vrh-repro@sha256:...
  synthetic_data: true
  disposable: true

success:
  impact: concrete-impact
  evidence:
    - reproduction test
    - clean-run log
    - source snapshot digest

discovery:
  source_first: true
  history_restricted: true
  internet_restricted: true
```

`network` may be `denied` or `allowlisted`. The scaffold deliberately does
not accept `open` or unspecified networking. `container_image` must be a
digest-pinned reference already present on the host (`name@sha256:...` or
`sha256:...`). `vrh repro` will not pull.
