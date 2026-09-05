import hashlib
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from soclab import __version__
from soclab.cli import app
from soclab.policy import OPA_VERSION, cached_opa_path, find_opa_binary, opa_asset
from soclab.policy import opa_binary as opa_module
from soclab.reports import PDF_EXTRA_HINT

runner = CliRunner()


@pytest.fixture
def no_opa(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """No OPA anywhere: not in the env, not on PATH, empty cache. Returns the cache root."""
    monkeypatch.setenv("SOCLAB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("SOCLAB_OPA_BINARY", raising=False)
    monkeypatch.delenv("SOCLAB_OPA_URL", raising=False)
    monkeypatch.setattr(opa_module.shutil, "which", lambda _name: None)
    return tmp_path / "cache"


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


def test_demo_without_opa_says_exactly_what_to_run(no_opa: Path) -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 1
    text = result.output + result.stderr
    assert "soclab opa install" in text
    assert "soclab demo --install-opa" in text
    assert "SOCLAB_OPA_BINARY" in text
    assert "Traceback" not in text


def test_opa_path_without_opa_exits_one(no_opa: Path) -> None:
    result = runner.invoke(app, ["opa", "path"])
    assert result.exit_code == 1
    assert "soclab opa install" in result.output + result.stderr


def test_opa_install_prints_url_and_checksum_and_caches(
    no_opa: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"fake opa"
    asset = opa_asset()
    monkeypatch.setitem(
        opa_module._ASSETS, (asset.system, asset.arch), (asset.filename, hashlib.sha256(payload).hexdigest())
    )
    monkeypatch.setattr(opa_module, "download_to_file", lambda _url, dest: dest.write_bytes(payload))
    result = runner.invoke(app, ["opa", "install"])
    assert result.exit_code == 0, result.output
    assert asset.url in result.output
    assert hashlib.sha256(payload).hexdigest() in result.output
    assert f"OPA {OPA_VERSION}" in result.output
    assert cached_opa_path().read_bytes() == payload
    assert find_opa_binary() == cached_opa_path()
    shown = runner.invoke(app, ["opa", "path"])
    assert shown.exit_code == 0 and shown.output.strip() == str(cached_opa_path())


def test_opa_install_refuses_tampered_download(no_opa: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(opa_module, "download_to_file", lambda _url, dest: dest.write_bytes(b"tampered"))
    result = runner.invoke(app, ["opa", "install"])
    assert result.exit_code == 1
    assert "sha256 mismatch" in result.output + result.stderr
    assert not cached_opa_path().exists()


def test_demo_install_opa_flag_runs_installer_first(no_opa: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The flag installs (and stops on a bad digest) before any campaign starts."""
    monkeypatch.setattr(opa_module, "download_to_file", lambda _url, dest: dest.write_bytes(b"tampered"))
    result = runner.invoke(app, ["demo", "--install-opa"])
    assert result.exit_code == 1
    text = result.output + result.stderr
    assert opa_asset().url in text and "sha256 mismatch" in text


def _scorecard(tmp_path: Path) -> Path:
    db = f"sqlite+pysqlite:///{tmp_path / 'e.sqlite'}"
    out = tmp_path / "reports"
    result = runner.invoke(
        app,
        ["campaign", "--mode", "baseline", "--scenario", "ATK-001", "--out", str(out), "--database-url", db],
    )
    assert result.exit_code == 0, result.output
    return out / "baseline-executive.json"


def test_report_text_needs_no_extra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788609600")
    scorecard = _scorecard(tmp_path)
    result = runner.invoke(app, ["report", str(scorecard), "--format", "text"])
    assert result.exit_code == 0, result.output
    assert "Executive assurance summary" in result.output
    assert "Recommended authority level: L1 Observe" in result.output
    assert "Date          2026-09-05 12:00 UTC" in result.output
    assert "mock / mock-investigator-v1" in result.output
    target = tmp_path / "summary.txt"
    written = runner.invoke(app, ["report", str(scorecard), "--format", "text", "--out", str(target)])
    assert written.exit_code == 0 and target.read_text(encoding="utf-8") == result.output


def test_report_pdf_writes_next_to_the_scorecard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pdf_text: Callable[[bytes], str]
) -> None:
    pytest.importorskip("reportlab")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1788609600")
    scorecard = _scorecard(tmp_path)
    result = runner.invoke(app, ["report", str(scorecard)])
    assert result.exit_code == 0, result.output
    default_target = scorecard.with_suffix(".pdf")
    assert default_target.exists() and str(default_target) in result.output
    data = default_target.read_bytes()
    assert data.startswith(b"%PDF-")
    text = re.sub(r"\s+", " ", pdf_text(data))
    assert "Executive assurance summary" in text
    assert "L1 Observe" in text
    explicit = tmp_path / "nested" / "summary.pdf"
    again = runner.invoke(app, ["report", str(scorecard), "--format", "pdf", "--out", str(explicit)])
    assert again.exit_code == 0 and explicit.read_bytes() == data


def test_report_pdf_without_extra_says_what_to_install(tmp_path: Path, hide_reportlab: None) -> None:
    scorecard = _scorecard(tmp_path)
    result = runner.invoke(app, ["report", str(scorecard)])
    assert result.exit_code == 1
    assert PDF_EXTRA_HINT in result.output
    assert not scorecard.with_suffix(".pdf").exists()
