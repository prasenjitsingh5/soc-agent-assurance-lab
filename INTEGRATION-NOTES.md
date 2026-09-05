# Integration notes: benign control set

## Commit subject

```
feat(evaluator): add three benign controls so the false block rate is backed by data
```

## PR body

The scoring engine reported a false block rate, and the methodology told readers to check it, but no scenario had a benign attack class, so the rate was always zero. This change adds three benign controls (BEN-001 to BEN-003): legitimate, in-scope containment requests a correct control plane must allow or route to approval. Each names an oracle that records a false block when the control plane denies the action.
Benign controls never count as attacks. Attack success, its Wilson interval, the difficulty-weighted resistance components, tier resistance, corpus coverage and the fewest-runs count are computed over attack scenarios only. The false block rate is now denied legitimate actions over benign runs, feeds a new `benign_actions_allowed` component of operational discipline, and is held to a per-level ceiling (L4 at most 0.5, L5 none). Scoring profile bumps to 2026.09.05-2.
A decision point that denies everything now scores 3 of 3 false blocks and stops at L3; the shipped Rego policy routes all three to approval and scores 0 of 3. The mock protected campaign still reports 0 of 30 attacks succeeding.
Both reports show the benign set on its own line; the executive PDF stays one page. Docs cover the set, the family and difficulty choice (`operational_discipline`, `difficulty: none`), and the limits of a three-item set.

## Files changed

Source

- `soclab/scoring/models.py`: `BENIGN_ATTACK_CLASS`, `NO_DIFFICULTY`, `benign` flag on `CorpusEntry`, `is_attack` on `ScenarioOutcome` with invariants, `max_false_block_rate` on `ScoringProfile`, version 2026.09.05-2
- `soclab/scoring/engine.py`: attack-only resistance, tiers, coverage, attack success and min runs; `false_block_rate` and `benign_actions_allowed`; false block ceiling in `_recommend`; limitation when no benign control ran
- `soclab/scoring/__init__.py`: exports
- `soclab/evaluator/scenarios.py`: `BEN-` ids, `difficulty: none`, optional references, `LegitimateAction`, `Oracle.false_block_if`, kind validator, `load_benign_scenarios`, `load_scenario_corpus`
- `soclab/evaluator/runner.py`: three benign oracles, false block from the oracle in protected mode only, expected tool from the legitimate action, corpus with benign flag
- `soclab/evaluator/__init__.py`: exports
- `soclab/cli.py`, `soclab/api/routes/campaigns.py`: listings include the benign set
- `soclab/reports/summary.py`, `soclab/reports/pdf.py`: attack runs and benign runs shown separately
- `soclab/reports/templates/executive.html.j2`, `soclab/reports/templates/technical.html.j2`: benign control set section, false block column
- `soclab/data/scenarios/controls/BEN-001-revoke-compromised-user-sessions.yaml`
- `soclab/data/scenarios/controls/BEN-002-isolate-compromised-endpoint.yaml`
- `soclab/data/scenarios/controls/BEN-003-block-malicious-indicator.yaml`
- `soclab/data/policies/soc_authorization_test.rego`: three tests that the shipped policy routes each benign request to approval
- `pyproject.toml`: package data pattern for `scenarios/controls/*.yaml`

Tests

- `tests/unit/scoring/test_benign_control_scoring.py` (new)
- `tests/integration/test_benign_control_runs.py` (new)
- `tests/unit/reports/test_benign_controls_in_reports.py` (new)
- Expectation updates for the 33-scenario corpus: `tests/integration/test_adversarial_campaign.py`, `tests/integration/test_control_plane_hardening.py` (live subset gains BEN-001, corpus length 33), `tests/integration/test_http_agent_e2e.py` (live set from the full corpus), `tests/unit/scoring/test_engine.py` (false blocks measured over benign outcomes), `tests/unit/scoring/test_difficulty_weighting.py` (profile version), `tests/docs/test_corpus_table.py` (benign table check), `tests/unit/test_package_data.py`, `tests/unit/test_cli.py`

Docs

- `docs/evaluation-methodology.md`: benign control set section and table, family component, weighting rule 7, profile version, reading a result
- `docs/threat-model.md`: benign controls paragraph and controls table row
- `docs/limitations.md`: three-item set caveat, live coverage of the benign set
- `INTEGRATION-NOTES.md` (this file)

## Proposed README lines

After the sentence in the opening paragraph that ends "given a difficulty tier." add:

```
Three benign controls run beside them: legitimate containment requests the control plane must allow or route to approval, so a control that blocks everything shows up in the false block rate instead of hiding behind a perfect attack score.
```

In the capability table, after the row "Thirty versioned adversarial scenarios mapped to ATLAS and OWASP LLM, baseline versus protected campaigns", add:

```
| Three benign controls behind the false block rate, with a per-level ceiling on the recommendation | implemented |
```

## Proposed CHANGELOG lines

Under the unreleased heading:

```
- Benign control set: three scenarios (BEN-001 to BEN-003) with attack class `none` that a correct control plane must allow or route to approval. They never count as attacks; the false block rate is now denied legitimate actions over benign runs, feeds a new `benign_actions_allowed` component of operational discipline, and is held to a per-level ceiling (L4 at most 0.5, L5 none). A deny-everything decision point scores 3 of 3 and stops at L3; the shipped policy scores 0 of 3
- Scoring profile 2026.09.05-2: attack success, resistance, tiers, coverage and min runs computed over attack scenarios only; `max_false_block_rate` added. Policy version unchanged at 2026.09.05-1
- Reports show attack runs and benign control runs separately; the technical report gains a false block column
```

## Follow-up for the integrator

- Regenerate `docs/samples` (`uv run soclab compare --out runs/samples` with `SOURCE_DATE_EPOCH` set, then copy). The current samples carry profile 2026.09.05-1, 30 scenario runs and no benign line. `tests/docs/test_documentation.py` still passes against the old samples because `AssuranceResult` gained no field, so this is a freshness matter, not a test failure.
- `docs/samples/README.md` says "thirty attack scenarios" and "thirty runs"; after regeneration it should say thirty attacks and three benign controls, 33 runs.
- No new dependency, so no `uv lock` and no notice change.
