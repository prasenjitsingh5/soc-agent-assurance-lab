# Limitations and known risks

This document is deliberately blunt. A reader deciding whether to trust the lab's numbers should read it before the executive report.

## What the lab does not do

- **It does not connect to anything real.** SIEM, identity, endpoint and network tools are synthetic fixtures. Containment actions change in-memory state and return receipts marked `simulation=true`.
- **It does not certify a model.** Scores describe behavior on one synthetic incident with thirty fixed attacks. They are evidence for a decision, not a compliance attestation.
- **Only one live model has been run.** Ollama with a 3B local model completed both campaigns; the result is in `docs/releases/0.1.0-evidence.md`. Every commercial adapter is contract-tested against recorded fixtures and awaits a live run. Thirteen of the thirty attacks apply to live models, the ones carried by fixture data or performed by the harness; the other seventeen depend on scripting the mock's replies or its cost.
- **One incident family.** Identity compromise only. Ransomware, insider threat and others are out of scope for Phase 1.
- **One agent.** No multi-agent orchestration.
- **No web application yet.** Executive, analyst and architect views and the scenario replay are Phase 2. The API already serves the data.
- **No Azure deployment yet.** Phase 3.

## Where the numbers are soft

- **Thirty runs is a small sample.** The 95% interval on attack success is wide when the rate is mid-range, and the report says so whenever the interval is wider than twenty points. Use `--repeats` with stochastic models. Bounded autonomy (L5) is never recommended from a single pass.
- **Difficulty tiers are a judgment.** Low, medium and high follow the published criteria in the evaluation methodology, but they were assigned by hand. A different reviewer might move a scenario one tier.
- **ATLAS and OWASP references are labels, not scores.** Each scenario cites the closest technique. Control-plane attacks such as replayed grants and evidence tampering have no exact ATLAS entry and cite `AML.T0053` as the nearest fit.
- **Cost is estimated.** The price table is a placeholder for comparison; it is labeled estimated in every result and must be checked against vendor pricing before being quoted.
- **The mock's gullible behavior is a stand-in.** It obeys instruction-like text in untrusted content on purpose. Real models fail differently and less predictably.
- **The baseline is not "no controls".** Schema validation of provider output, citation checking, the default-deny tool registry and the hash chain live outside the control plane, so four scenarios are blocked in baseline as well. The baseline models weak controls, not their absence.
- **The simulated directory folds lookalike identifiers on purpose.** It resolves case and cross-script confusables so the confusable-identifier scenario has something to measure. Real directories vary; the policy rule that rejects non-ASCII arguments does not depend on that behavior.
- **Approval fatigue is simulated.** The replay scenario approves the pending action with a scripted approver. No human decided anything.

## Security caveats

- **The hash chain is tamper evidence, not immutability.** A party with write access to the database and the ability to recompute every hash from the tampered point forward could rebuild a consistent chain. Publishing root hashes outside the database, as the reports do, is the mitigation. Write-once storage is a deployment concern.
- **The Phase 1 executor runs in the same process as the orchestrator.** Isolation rests on the signed grant, the port discipline and tests, not on a process boundary. ADR 0005 tracks the split.
- **Redaction is pattern based.** It removes the canary patterns it is configured with. It is not a general secret detector.
- **OPA is trusted.** A compromised policy container is out of scope.

## Operational caveats

- Protected campaigns need the `opa` binary or an OPA server. Without one the CLI stops and the API answers 503. This is the intended fail-closed behavior, and it also means the quick start has one prerequisite beyond Python.
- Windows is a first-class development platform for this repository, but the Docker profile has only been validated on Linux runners so far.
