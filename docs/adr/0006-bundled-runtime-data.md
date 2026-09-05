# ADR 0006: Runtime data ships inside the package

Date: 2026-09-05. Status: accepted. Amends ADR 0001.

## Context

ADR 0001 kept the Rego policy and the scenario files outside the Python
package, at `policies/rego` and `scenarios`. The code located them relative
to the repository root, and the Docker image copied them in and set two
environment variables. A wheel built from the project therefore could not run
`soclab demo` on its own, which ruled out `uvx soclab demo` and `pip install
soclab` as a first contact path.

Two copies, one canonical and one packaged, were rejected: they drift, and
symbolic links do not survive a Windows checkout.

## Decision

There is one copy, inside the package, under `soclab/data/`:

- `soclab/data/scenarios/attacks/*.yaml` and `soclab/data/scenarios/incidents/*.yaml`
- `soclab/data/policies/*.rego`, including the Rego unit tests

`soclab.data` resolves paths with `importlib.resources`. The environment
variables `SOCLAB_SCENARIO_DIR` and `SOCLAB_POLICY_DIR` still override the
locations for experiments. `pyproject.toml` lists the files as package data,
and a unit test fails when a runtime file under `soclab/` is not covered by
those patterns. The Compose file mounts `soclab/data/policies` into the OPA
container, and `make policy-test` runs `opa test` against the same folder.

## Consequences

- An installed wheel is self sufficient. The release workflow proves it by
  installing the wheel into an empty environment and running the CLI from a
  directory outside the checkout.
- The Docker image no longer copies data folders or sets path variables.
- Contributors add scenarios under `soclab/data/scenarios/attacks/`. The
  contributing guide and the policy guide point there.
- ADR 0001's import discipline is unchanged; only the location of non-Python
  assets moves.
