from pathlib import Path

import pytest
from typer.testing import CliRunner

from soclab import __version__
from soclab.cli import app
from soclab.policy import find_opa_binary

runner = CliRunner()


def test_version_and_listings() -> None:
    assert runner.invoke(app, ["version"]).output.strip() == __version__
    scenarios = runner.invoke(app, ["scenarios"])
    assert scenarios.exit_code == 0 and "ATK-001" in scenarios.output
    providers = runner.invoke(app, ["providers"])
    assert (
        providers.exit_code == 0
        and "mock" in providers.output
        and "credentials not configured" in providers.output
    )


def test_baseline_investigation_and_campaign(tmp_path: Path) -> None:
    db = f"sqlite+pysqlite:///{tmp_path / 'e.sqlite'}"
    result = runner.invoke(app, ["investigate", "--mode", "baseline", "--database-url", db])
    assert result.exit_code == 0, result.output
    assert '"status": "complete"' in result.output
    out = tmp_path / "reports"
    campaign = runner.invoke(
        app,
        ["campaign", "--mode", "baseline", "--scenario", "ATK-001", "--out", str(out), "--database-url", db],
    )
    assert campaign.exit_code == 0, campaign.output
    assert "baseline: attack success 100%" in campaign.output
    assert (out / "baseline-executive.html").exists()
    verify = runner.invoke(app, ["verify-chain", "--database-url", db])
    assert verify.exit_code == 0 and "valid" in verify.output


@pytest.mark.policy
@pytest.mark.skipif(find_opa_binary() is None, reason="opa binary not installed")
def test_compare_writes_both_reports(tmp_path: Path) -> None:
    db = f"sqlite+pysqlite:///{tmp_path / 'e.sqlite'}"
    result = runner.invoke(app, ["compare", "--out", str(tmp_path / "cmp"), "--database-url", db])
    assert result.exit_code == 0, result.output
    assert "protected: attack success 0%" in result.output
    assert (tmp_path / "cmp" / "executive.html").exists()
    assert (tmp_path / "cmp" / "technical.json").exists()
