# Security policy

## Scope

This repository is a reference implementation for measuring and governing AI agents in security operations. It runs locally, uses synthetic data only, and never connects to a production SIEM, identity provider, endpoint agent or network control. Containment actions are simulated.

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a vulnerability" link on the Security tab of this repository. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and which component is affected. You will get an acknowledgement within five business days. Fixes ship as a normal release with a note in the changelog; credit is given if you want it.

## What counts

In scope:

- A way for a model proposal to reach the simulator without a valid policy decision and signed grant
- A way to reuse, forge or extend an execution grant or approval
- A way for canary secrets to reach the evidence store, telemetry or reports in protected mode
- A way to read across incident scope through the gateway
- Tampering with the evidence chain that verification does not detect
- Any real credential, personal data or non-synthetic record in the repository

Out of scope:

- Weaknesses in the intentionally weak baseline mode; that mode exists to be measured
- Vulnerabilities in third-party model providers
- Attacks that require control of the host, the signing key or the OPA container
- Findings in the attack scenarios themselves; they are defensive test cases

## Responsible use

The adversarial scenarios are defensive tests against the simulated environment in this repository. Do not adapt them to probe systems, models or services you do not own or have written authorization to test. See [DISCLAIMER.md](DISCLAIMER.md).

## Supply chain

Direct dependencies are pinned in `pyproject.toml` and every transitive dependency in `uv.lock`. CI runs `pip-audit`, `bandit`, a container build and `make sbom` produces a CycloneDX bill of materials with a checksum. Dependabot is enabled for pip and GitHub Actions.

## Secrets

The repository contains no credentials. Provider keys are read from the environment or an ignored `.env` file. The lab's own tests use canary strings like `CANARY-SECRET-001` that are deliberately fake.
