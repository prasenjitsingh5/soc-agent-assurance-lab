# Limitations and known risks

This document is deliberately blunt. A reader deciding whether to trust the lab's numbers should read it before the executive report.

## What the lab does not do

- **It does not connect to anything real.** SIEM, identity, endpoint and network tools are synthetic fixtures. Containment actions change in-memory state and return receipts marked `simulation=true`.
- **It does not certify a model.** Scores describe behavior on one synthetic incident with twelve fixed attacks. They are evidence for a decision, not a compliance attestation.
- **Only one live model has been run.** Ollama with a 3B local model completed both campaigns; the result is in `docs/releases/0.1.0-evidence.md`. Every commercial adapter is contract-tested against recorded fixtures and awaits a live run. Only the two fixture-driven attacks apply to live models; the other ten depend on scripting the mock.
- **One incident family.** Identity compromise only. Ransomware, insider threat and others are out of scope for Phase 1.
- **One agent.** No multi-agent orchestration.
- **No web application yet.** Executive, analyst and architect views and the scenario replay are Phase 2. The API already serves the data.
- **No Azure deployment yet.** Phase 3.

## Where the numbers are soft

- **Twelve runs is a small sample.** The 95% interval on attack success is wide and the report says so. Use `--repeats` with stochastic models.
- **Cost is estimated.** The price table is a placeholder for comparison; it is labeled estimated in every result and must be checked against vendor pricing before being quoted.
- **The mock's gullible behavior is a stand-in.** It obeys instruction-like text in untrusted content on purpose. Real models fail differently and less predictably.
- **The baseline is not "no controls".** Schema validation of provider output and the default-deny tool registry live in the orchestrator, so three scenarios are blocked in baseline as well. The baseline models weak controls, not their absence.

## Security caveats

- **The hash chain is tamper evidence, not immutability.** A party with write access to the database and the ability to recompute every hash from the tampered point forward could rebuild a consistent chain. Publishing root hashes outside the database, as the reports do, is the mitigation. Write-once storage is a deployment concern.
- **The Phase 1 executor runs in the same process as the orchestrator.** Isolation rests on the signed grant, the port discipline and tests, not on a process boundary. ADR 0005 tracks the split.
- **Redaction is pattern based.** It removes the canary patterns it is configured with. It is not a general secret detector.
- **OPA is trusted.** A compromised policy container is out of scope.

## Operational caveats

- Protected campaigns need the `opa` binary or an OPA server. Without one the CLI stops and the API answers 503. This is the intended fail-closed behavior, and it also means the quick start has one prerequisite beyond Python.
- Windows is a first-class development platform for this repository, but the Docker profile has only been validated on Linux runners so far.
