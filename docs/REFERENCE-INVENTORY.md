# Open-Source Reference Inventory

Reviewed September 4, 2026. Revalidate versions, interfaces, licenses and security posture before implementation.

| Project | Role in our design | Intended use |
|---|---|---|
| [Agentic SOC Platform](https://github.com/FunnyWolf/agentic-soc-platform) | Competitive reference | Study SOC case, enrichment and playbook patterns; do not reproduce the platform |
| [AI-SOC-Agent](https://github.com/M507/ai-soc-agent) | Competitive reference | Study integration boundaries and investigation workflows |
| [PouchNexus](https://github.com/NathanCavalcanti/pouchnexus) | Competitive reference | Study IOC, ATT&CK and report workflows |
| [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | Security reference | Compare identity, policy, sandbox and evidence patterns |
| [AISecOps Interceptor](https://github.com/viplavfauzdar/aisecops-interceptor) | Security reference | Compare runtime interception, approvals and audit patterns |
| [IntentFrame](https://github.com/intentframe/intentframe) | Security reference | Compare separation of proposal, policy and execution |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | Planned dependency | Deterministic authorization and policy tests |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | Planned dependency | Declarative evaluation and adversarial regression in CI |
| [Microsoft PyRIT](https://github.com/microsoft/PyRIT) | Optional integration | Advanced authorized red-team campaigns |
| [NVIDIA garak](https://github.com/NVIDIA/garak) | Optional reference | Model-vulnerability scanning concepts |
| [LiteLLM](https://github.com/BerriAI/litellm) | Optional dependency | Broad provider gateway behind our canonical interface |
| [OpenAI Python SDK](https://github.com/openai/openai-python) | Provider dependency | Native OpenAI and compatible adapter behavior |
| [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python) | Provider dependency | Native Anthropic adapter behavior |
| [Google Gen AI SDK](https://github.com/googleapis/python-genai) | Provider dependency | Gemini and Vertex adapter behavior |
| [Arize Phoenix](https://github.com/Arize-ai/phoenix) | Optional adapter | Local observability and evaluation |
| [OpenInference](https://github.com/Arize-ai/openinference) | Planned dependency | Portable AI trace conventions over OpenTelemetry |
| [MLflow](https://github.com/mlflow/mlflow) | Primary optional enterprise adapter | Experiment tracking, evaluation datasets, traces and comparisons |
| [MITRE ATT&CK CTI](https://github.com/mitre-attack/attack-stix-data) | Data reference | Versioned ATT&CK mappings for synthetic incidents |

## Reuse rules

1. Prefer documented APIs and adapters over copied source.
2. Pin each dependency to a reviewed version.
3. Record the dependency's license and notices.
4. Generate and review an SBOM.
5. Keep our canonical contracts independent of third-party SDK types.
6. Treat provider support as tested only after its contract and scenario tests pass.
7. Label optional integrations accurately.
8. Document material security findings affecting a selected dependency.

## Differentiation guardrail

The original contribution must remain focused on:

- SOC-specific contextual authorization;
- measurable control effectiveness;
- evidence-based authority levels;
- baseline-versus-protected replay;
- cross-model assurance comparison;
- transparent AI security economics; and
- decision-ready evidence packages.

If a proposed feature merely recreates a mature capability in one of the projects above, integrate, adapt or defer it.

