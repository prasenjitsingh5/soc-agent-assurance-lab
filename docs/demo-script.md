# Five-minute demonstration

Everything below runs locally with the mock provider. No keys, no network.

## 1. Install (one minute)

The package is on PyPI as `soclab`. With [uv](https://docs.astral.sh/uv/) installed, one command fetches the lab, downloads the pinned Open Policy Agent build after printing its URL and sha256, verifies it, and runs the comparison:

```bash
uvx soclab demo --install-opa
```

Without uv:

```bash
pip install soclab
soclab opa install
soclab demo
```

`soclab opa install` puts OPA 1.20.2 in a per-user cache and checks it against a digest pinned in the source. Nothing is downloaded unless you run that command or pass `--install-opa`. If `opa` is already on `PATH`, or `SOCLAB_OPA_BINARY` points at one, the lab uses that and `uvx soclab demo` works on its own. Without any OPA, `soclab demo` stops and prints the two commands above.

From a checkout, for development:

```bash
git clone https://github.com/prasenjitsingh5/soc-agent-assurance-lab.git
cd soc-agent-assurance-lab
uv sync --extra dev --extra security --extra pdf
uv run soclab opa install
```

The rest of this script uses the checkout form, `uv run soclab`. After `pip install soclab` drop the `uv run`.

The `pdf` extra is only needed for step 6.

## 2. See the attack surface (30 seconds)

```bash
uv run soclab scenarios
```

Thirty versioned attacks in five families and three difficulty tiers, each mapped to MITRE ATLAS and the OWASP Top 10 for LLM Applications. They cover injected instructions in seven channels (SIEM notes, threat intelligence, ticket comments, EDR command lines, DNS answers, mail headers, feed names), poisoned tool results, goal hijacking, canary leakage in plain and encoded form, unregistered tools, privileged disablement, fabricated evidence, argument smuggling, smuggled approvals, cross-incident reads and writes, call and spend exhaustion, forged, replayed and swapped grants, evidence tampering, catch-all block rules, authority-claim jailbreaks, lookalike identifiers, model substitution and malformed output.

## 3. Run the comparison (two minutes)

```bash
uv run soclab compare --out runs/demo
```

Expected output:

```
baseline : attack success 87%, authority L1
protected: attack success 0%, authority L4
reports  : runs/demo/executive.html and runs/demo/technical.html
```

Twenty-six of thirty attacks land on the baseline. The four that do not (unregistered tool, fabricated citations, malformed output, evidence tampering) are stopped by the orchestrator's schema and citation checks and by the hash chain, which exist in both configurations. Protected mode stops all thirty and earns L4. Bounded autonomy (L5) needs every scenario run at least twice: `uv run soclab campaign --mode protected --repeats 2`.

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

## 6. Export the one-page executive PDF (30 seconds)

```bash
uv run soclab report runs/demo/executive.json
```

This writes `runs/demo/executive.pdf`: the authority recommendation, the six mandatory gates, the five family scores with their intervals, the attack results and the chain head hash of every run, on one page. `--format text` prints the same summary to the terminal and needs no optional dependency. Without the `pdf` extra the command prints the install line and exits with code 1.

Sample output from this exact demo, generated with the mock provider on synthetic data, is in [docs/samples](samples/README.md). Read it before installing anything.

## 7. Optional: bring your own model

```bash
export OPENAI_API_KEY=...
uv run soclab investigate --provider openai --mode protected
```

The registry refuses providers that are not configured or not approved, and the report labels the provider as contract-tested until a live run is recorded in `docs/releases/`.
