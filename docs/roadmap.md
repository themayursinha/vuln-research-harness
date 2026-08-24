# Roadmap

## Phase 1: foundation (current)

- [x] Campaign contract and fail-closed validation
- [x] Approach-family registry with blocked-path reopening rule
- [x] Hash-linked append-only evidence ledger
- [x] `vrh init` and `vrh validate`

## Phase 2: controlled execution

- [ ] Campaign directory layout and snapshot manifest
- [ ] Structured worker request/result schema
- [ ] Coordinator round state machine
- [ ] Read-only executor interface
- [ ] Explicit executor capability checks

## Phase 3: validation

- [ ] Minimal reproduction runner
- [ ] Disposable container or microVM adapter
- [ ] Network boundary verification
- [ ] Independent adversarial validator lane
- [ ] Evidence export and disclosure package

## Phase 4: pilot

- [ ] Choose one authorized open-source MCP server with a local fixture
- [ ] Run a bounded four-worker campaign
- [ ] Measure approach diversity, false positives, evidence completeness,
      runtime, and model cost
- [ ] Publish a methodology note only after the workflow is reproducible

The first pilot must not target live infrastructure and must not become a
large autonomous agent platform before the contract, evidence, and isolation
semantics are proven.
