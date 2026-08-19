<!--
Author:  Landen Stecker
Date:    2026-08-19
Version: 0.2.1
Summary: Public README for aegis-atoms. Atom plane and bounded judge as source.
-->

<div align="center">

# Aegis atoms

The atom plane and a bounded judge, as source. The allowlist that gates tool calls is capability-gate, a separate roof.

The floor decides. The judge doubts. The box contains. The audit attests.

![Atoms harness](https://img.shields.io/badge/Atoms%20harness-7%2F16%20hard--deny-1f6feb)
![mode](https://img.shields.io/badge/mode-observe-informational)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![status](https://img.shields.io/badge/status-observe%20research%20build-blueviolet)

</div>

---

An atom is a fact with no opinion. It cannot authorize. Its decision is DENY or ABSTAIN, never yes. Polarity and strength live on the edge. The effect lives on the control. The rollup combines them deny-overrides, tracking maximum support and maximum contradiction independently rather than summing, so an allow that outranks a block cannot be expressed and argument order cannot change the result. Keeping the three objects apart is the point: the moment an atom carries its own effect it stops being reusable and becomes a decision.

Support and contradiction both firing is CONFLICTING, and that escalates rather than guessing. That case is the named handoff to the box.

This repository is source. It is not a mount.

| | Here | Live, on the Hermes aegis profile |
|---|---|---|
| Allowlist floor | not this roof | capability-gate, enforce |
| Triad plugin | source | not mounted |
| Judge | subtract-only, proven | `judge_apply_verdict=False` |
| Irreversible ops | `evaluate_tool_call` defaults False | not enabled |
| Catalog | `catalog/Aegis-Atoms-v0.yaml`: 15 atoms, 2 delegates | mostly dormant |

Two caller sets exist here on purpose. `property_fuzzer.py` runs the apply path with `judge_apply_verdict=True` to earn the subtract-invariant receipt, and the observe path with False to mirror the live mount. Both are harness callers. Neither is a tool call.

`evaluate_tool_call` defaults `judge_apply_verdict` to True. A caller who omits the argument applies. Pass False on purpose.

BREAK lives in `evidence/j3/negative-controls.md`. Those pytest functions monkeypatch the wire so the invariant fails. Going red is the proof the detector works. A green 10k run whose control was never exercised is a green on nothing.

Inventory: **28** root Python modules, **2** evidence directories (`evidence`, `evidence/j3`), two receipted 10k runs (apply subtract + observe telemetry). No line-count in this file.

## Four-plane authority

> The floor decides. The judge doubts. The box contains. The audit attests.

That sentence is from the containment topic, quoted verbatim. This repository is not all four planes.

| Plane | Where it lives | Grade here |
|---|---|---|
| Floor (allowlist) | `Steck43/capability-gate` on `profiles/aegis` | live enforce, not this repo |
| Floor (atom plane) | this tree | source-present, not mounted on this roof |
| Judge | this tree (`bounded_judge.py`, J3) | proven, subtract-only. Live mount keeps `apply_verdict=False` |
| Box | separate Rust tree | not consumed by this plugin |
| Audit | vault ledger | not shipped in git |

Memory is a governed surface, not a fifth plane.

## Why this exists

An agent thinks and it acts. Thinking is text. Acting is a tool call. A static allowlist is necessary and not sufficient: it is structurally blind to capability aliasing, argument evasion, context, composition, and injection. Atoms are polarity-free facts. Edges carry polarity. Controls carry effect. Combination is deny-overrides.

## How a decision is made

```mermaid
flowchart TD
    A([Proposed tool call]) --> PEP[PEP · intercept before the tool runs]
    PEP --> PDP{PDP · evaluate · pre-tool}
    subgraph PDP["PDP evaluation · pre-tool call"]
      ATOMS[Atoms<br/>polarity-free facts] --> EDGES[Edges<br/>polarity + strength]
      EDGES --> CTRL[Controls<br/>carry the effect]
      CTRL --> ROLL[Rollup<br/>deny-overrides · max support and contradiction]
    end
    PDP --> ATOMS
    ROLL -->|clean verdict| ENF[PEP · enforce]
    ROLL -->|CONFLICTING| BOX[Box · isolation-layer]
    BOX -->|still contradicts| JUDGE[Bounded Judge<br/>subtract-only]
    JUDGE -. cannot widen or approve .-> ENF
    JUDGE -->|low confidence / retry cap| HUMAN([Escalate to human])
    ENF --> OUT([allow · deny · escalate])
```

PDP evaluate is a pre-tool call. The tool has not run yet. Pre-tool call goes to atoms. A contradiction the rollup cannot settle goes to the box.

This ordering is design intent, not a forced path. Today a tool call meets the allowlist and runs. It does not have to enter the atom plane, does not have to enter the box, and does not pay a judge.

Observe means consult plus telemetry. The engine can compute a subtract and then discard it when `judge_apply_verdict` is False. That is how the Hermes profile plugin is wired. This public extract is source-present, not a live mount.

## The three-object model

| Object | Carries | Never carries |
|---|---|---|
| **Atom** | a polarity-free fact ("this path resolves outside its root") | polarity, effect, framework mapping |
| **Edge** | polarity (`supports` / `contradicts`) and strength | the effect |
| **Control** | the effect (`allow` to `block`) and the framework mappings | the raw fact |

## The four governed surfaces

| Surface | Atom | Fires when | Certainty |
|---|---|---|---|
| **Action gating** | path · shell | a path resolves outside its allowed root; a command carries executable structure the schema forbids | structural · `1.0` |
| **Content detection** | indirect marker · output replication | incoming content carries known prompt-injection markers; agent output mirrors an injection-bearing untrusted input | heuristic · `< 1.0` |
| **Memory governance** | flow | secret-origin data reaches a durable-note or egress sink | structural · `1.0` |
| **Supply chain** | tool integrity · undeclared egress | an invoked tool's version or declared metadata drifts from its approved baseline | structural · `1.0` |

## What the suite measures

Two harnesses. Do not collapse the numbers.

**Adversarial suite (atoms KPI):** **7/16** hard-deny from `adversarial_suite.ALL_CASES` (**18** callables). Breakdown pinned in `tests/test_adversarial_suite.py`: 16 attack (`CAUGHT-NAIVE=7`, `FALSE-ALLOW=8`, `HALTED=1` for H1; H1 is in the 16, not in the hard-deny numerator) + 2 benign (`CORRECT-ALLOW=1`, `FALSE-DENY=1`). Fixture-era 8/16 is not the live KPI.

**CG Stage-1 lab** is a different harness on the capability-gate roof. Name which suite when you cite a tally.

Framework mappings reference OWASP (LLM and Agentic Top 10), MITRE ATLAS `v2026.06` (`mitre-atlas/atlas-data` `dist/v6/ATLAS-2026.06.yaml`), and NIST AI RMF, and live on the control, not the atom.

## The bounded judge

The judge can concur, flag, tighten, or escalate. It cannot issue a floor verdict, and it cannot widen or approve. Receipts: `evidence/j3/j3-property-10k.json` (apply) and `evidence/j3/j3-observe-telemetry-10k.json` (observe).

## History

This code lived in-tree in a Hermes-agent fork under `aegis-plugins/aegis-atoms`. History stays there. A public extract is a deliberate allowlist copy into a new repository, not a dump of the fork, and not a Nous Research LICENSE.

## Status

**Observe.** Capability-gate stays the live allowlist. Atoms enforce and a live `apply_verdict=True` mount are a separate GO.

---

<div align="center">

Built by **Landen Stecker** · CISSP · M.S. AI, Santa Clara University

</div>
