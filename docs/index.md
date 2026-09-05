# SOC Agent Assurance Lab

## The question

Before a security team lets an AI agent touch an incident, someone decides how much authority it gets: observe only, recommend, act with a human approving each step, or act alone inside narrow limits. That decision is usually made on a demo. This lab replaces the demo with evidence.

The lab runs a synthetic identity-compromise investigation through an agent twice, once with weak controls and once through a deterministic control plane, and attacks both runs with twelve fixed adversarial scenarios. Every model turn, tool call, policy decision, approval and execution lands in a hash-chained evidence store. The score, the mandatory gates and the recommended authority level come out of that record, not out of a hunch.

## The invariant

```
model proposes  ->  control gateway normalizes  ->  policy decides  ->  executor acts
```

The model never executes. The gateway builds the authorization context itself. Open Policy Agent returns allow, allow with obligations, require approval or deny. A separate executor, holding a signed single-use grant, is the only component that changes simulated state. Any outage in that chain fails closed.

## The five minute path

1. Install with `uv sync --extra dev --extra security` and put the `opa` binary on PATH. See the [quickstart](quickstart.md).
2. Run `uv run soclab compare --out runs/demo` with the built-in mock provider. No keys, no network.
3. Open `runs/demo/executive.html`. The first block is the recommended authority level and the gate status.
4. Run `uv run soclab verify-chain`, edit one byte in the evidence database, run it again and watch it fail.

The [demo script](demo-script.md) walks through each step with the expected output.

## Where to read next

| If you want to know | Read |
|---|---|
| How the pieces fit and which are implemented, simulated or planned | [Architecture](architecture.md) |
| What the adversary can and cannot do | [Threat model](threat-model.md) |
| How a campaign is scored and what a gate failure means | [Evaluation methodology](evaluation-methodology.md) |
| How the Rego package decides and how to change it | [Policy guide](policy-guide.md) |
| How to plug in your own model | [Custom provider](custom-provider.md) and [Provider compatibility](provider-compatibility.md) |
| Why the numbers should not be over-read | [Limitations](limitations.md) |
| The standing rules for changing the code | [Engineering standards](engineering-standards.md) and the decision records |
| What was verified before each release | [Releases](releases/0.1.0-evidence.md) |

## Status labels

Every capability in these pages carries one label: implemented, simulated, tested, optional integration, reference architecture or planned. The lab does not claim to be production ready, and [Limitations](limitations.md) says why.

## Boundaries

No real SIEM, identity, endpoint or network system is ever contacted. All data is synthetic. Containment actions are simulated and return receipts that say so. The attack scenarios are defensive tests against the in-repo simulator. Read the [disclaimer](DISCLAIMER.md) and the [security policy](SECURITY.md) before relying on anything here.

Source, issues and pull requests: [github.com/prasenjitsingh5/soc-agent-assurance-lab](https://github.com/prasenjitsingh5/soc-agent-assurance-lab). Apache-2.0.
