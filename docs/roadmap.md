# Roadmap

## Phase 1: foundation

- [x] Campaign contract and fail-closed validation
- [x] Approach-family registry with blocked-path reopening rule
- [x] Hash-linked append-only evidence ledger
- [x] `vrh init` and `vrh validate`

## Phase 2: controlled execution

- [x] Campaign directory layout and snapshot manifest
- [x] Structured worker request/result schema
- [x] Coordinator round state machine
- [x] Read-only executor interface (manual inbox executor, v1)
- [x] Explicit executor capability checks (fail-closed gate)

## Phase 3: validation

- [x] Minimal reproduction runner (`vrh repro`)
- [x] Disposable container adapter (digest-pinned local image; process-local namespaces remain the unit-test fallback)
- [x] Network boundary verification (`vrh verify-sandbox`; inspects created container HostConfig)
- [x] Independent adversarial validator lane (`vrh adversarial`)
- [x] Evidence export (repro outcomes + validation reports as JSON)
- [x] CI: CodeQL + govulncheck

## Phase 4: pilot (current)

- [x] Reference fixture campaign (`campaigns/fixture-lab`)
- [x] Choose one authorized open-source MCP server with a local fixture
      (`campaigns/mcp-filesystem`: official filesystem server)
- [ ] Seed and dispatch a bounded four-worker campaign
      (`vrh families seed` + `vrh round plan . 4`; workers still write
      result envelopes through the inbox — no fabricated evidence)
- [ ] Measure approach diversity, false positives, evidence completeness,
      runtime, and model cost
- [ ] Publish a methodology note only after the workflow is reproducible

The first pilot must not target live infrastructure and must not become a
large autonomous agent platform before the contract, evidence, and isolation
semantics are proven.
