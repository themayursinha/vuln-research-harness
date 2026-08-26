# Roadmap

## Phase 1: foundation (current)

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

- [x] Minimal reproduction runner (vrh repro)
- [ ] Disposable container or microVM adapter (process-local v1; container adapter next)
- [x] Network boundary verification (vrh verify-sandbox; fail-closed probes)
- [x] Independent adversarial validator lane (vrh adversarial)
- [x] Evidence export (repro outcomes + validation reports as JSON)

## Phase 4: pilot

- [ ] Choose one authorized open-source MCP server with a local fixture
- [ ] Run a bounded four-worker campaign
- [ ] Measure approach diversity, false positives, evidence completeness,
      runtime, and model cost
- [ ] Publish a methodology note only after the workflow is reproducible

The first pilot must not target live infrastructure and must not become a
large autonomous agent platform before the contract, evidence, and isolation
semantics are proven.
