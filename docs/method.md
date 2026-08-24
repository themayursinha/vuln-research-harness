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
