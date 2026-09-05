# Sample reports

These files are the output of one `soclab compare` run with the built-in mock provider on the lab's synthetic incident and its twelve attack scenarios. No real system, model, credential or data was involved. They are here so a visitor can see what the lab produces before installing anything. Each report says so in its own footer.

| File | What it is |
|---|---|
| [mock-protected-executive-report.html](mock-protected-executive-report.html) | Executive report for the protected campaign, with the baseline comparison |
| [mock-protected-technical-report.html](mock-protected-technical-report.html) | Technical report: every scenario, policy decision, receipt and chain verification |
| [mock-protected-scorecard.json](mock-protected-scorecard.json) | JSON scorecard the reports are rendered from |
| [mock-protected-executive-summary.pdf](mock-protected-executive-summary.pdf) | One-page executive PDF written by `soclab report` |

## What they show

| Mode | Attack success | Gate failures | Recommended authority |
|---|---|---|---|
| baseline | 9 of 12 (75%) | sensitive_data_leakage | L1 Observe |
| protected | 0 of 12 (0%) | none | L4 Act with approval |

The composite score moves from 0.70 to 0.87. The 95% interval on the protected attack success rate is 0% to 24%, because twelve runs is a small sample. The reports say so.

## How they were made

```bash
export SOURCE_DATE_EPOCH=1788609600
uv run soclab compare --out runs/samples --database-url sqlite+pysqlite:///./runs/samples.sqlite
uv run soclab report runs/samples/executive.json --out runs/samples/executive.pdf
```

`SOURCE_DATE_EPOCH` pins the report date to 2026-09-05 12:00 UTC so the PDF bytes are reproducible. Running the same commands again produces new campaign and run ids and new chain hashes; every score and the recommendation stay the same because the mock provider is deterministic.

The scorecard validates against the current `AssuranceResult` contract; `tests/docs/test_documentation.py` checks that, the labels above, the size of this folder and the absence of local paths.

Status labels for the code behind these files: implemented, simulated data. Read [../limitations.md](../limitations.md) before relying on any figure, and [../demo-script.md](../demo-script.md) to reproduce the run.
