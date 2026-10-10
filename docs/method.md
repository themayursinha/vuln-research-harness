# Method

VRH models vulnerability research as a controlled search over an attack-surface
and capability graph.

## Campaign phases

1. **Contract**: define target snapshot, authorization, attacker capabilities,
   deployment assumptions, concrete impact, and evidence artifacts.
2. **Portfolio**: start multiple incompatible approach families instead of
   assigning every worker the same strategy.
3. **Investigation**: agents return code paths, hypotheses, attempted
   mechanisms, and artifacts. The registry records active, blocked, or
   exhausted families.
4. **Synthesis**: the coordinator compares results, splits converged families,
   and opens a new round only when it has a specific reason.
5. **Adversarial validation**: an independent worker tries to disprove each
   concrete candidate and checks attacker preconditions.
6. **Reproduction**: execute a minimal test, then a realistic disposable
   deployment, both from the pinned source snapshot.
7. **Closure**: produce a disclosure package, or record the exact remaining
   gap and why the route is closed.

## Search state

The coordinator must preserve independence early. A family is blocked when
its current mechanism is exhausted. Reopening requires a materially new
mechanism, not a rephrasing of the same idea. This is the anti-whack-a-mole
rule.

## Evidence standard

A model report is a lead, not evidence. Evidence is an artifact such as:

- source path and relevant input trace;
- deterministic reproduction test;
- clean-run output and environment digest;
- minimized fixture or packet;
- independent validation result;
- impact proof using synthetic data only.

The claim must never exceed the strongest artifact.

## Code map

`vrh codemap` indexes the pinned snapshot into functions and direct call
edges. `vrh codemap reach` lists the files reachable from an entry point.
`vrh codemap slice` keeps that file set only when it fits a bound, and
`vrh round plan` can attach the slice to each worker request in the round.

The map is syntactic: Go functions and methods, Python `def`, and JavaScript
or TypeScript `function` declarations. Ambiguous or unresolved calls are not
treated as reachable. Python imports resolve only to a same-directory module
file. JavaScript and TypeScript imports resolve only to a relative file in
the snapshot. It is not a type checker, a taint engine, or a weakness lens,
and a slice is not evidence.
