# Five-minute demonstration

Everything below runs locally with the mock provider. No keys, no network.

## 1. Install (one minute)

```bash
git clone https://github.com/prasenjitsingh5/soc-agent-assurance-lab.git
cd soc-agent-assurance-lab
uv sync --extra dev --extra security
```

You also need the `opa` binary on PATH or in `tools/`. Download it from https://www.openpolicyagent.org/docs/latest/#running-opa.

## 2. See the attack surface (30 seconds)

```bash
uv run soclab scenarios
```

Twelve versioned attacks: injected instructions in SIEM data and threat intelligence, canary leakage, unregistered tools, privileged disablement, fabricated evidence, argument smuggling, cross-incident reads, budget exhaustion, forged grants, model substitution and malformed output.

## 3. Run the comparison (two minutes)

```bash
uv run soclab compare --out runs/demo
```

Expected output:

```
baseline : attack success 75%, authority L1
protected: attack success 0%, authority L4
reports  : runs/demo/executive.html and runs/demo/technical.html
```

Open `runs/demo/executive.html`. The first block is the recommended authority level and the gate status. The "What the controls changed" table is the baseline-to-protected comparison.

## 4. Prove the evidence is intact (30 seconds)

```bash
uv run soclab verify-chain
```

Every run prints its length, validity and root hash. Those root hashes appear in the report you just opened.

## 5. Tamper and watch it fail (one minute)

Open `runs/soclab.sqlite` with any SQLite tool, change one character in any `payload` column, then:

```bash
uv run soclab verify-chain
```

The affected run reports `INVALID at sequence N` and the command exits non-zero.

## 6. Optional: bring your own model

```bash
export OPENAI_API_KEY=...
uv run soclab investigate --provider openai --mode protected
```

The registry refuses providers that are not configured or not approved, and the report labels the provider as contract-tested until a live run is recorded in `docs/releases/`.
