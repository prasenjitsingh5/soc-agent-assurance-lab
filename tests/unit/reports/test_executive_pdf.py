"""PDF rendering: deterministic bytes, one page, key fields readable, clear message without the extra."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from soclab.reports import (
    PDF_EXTRA_HINT,
    PdfSupportMissingError,
    pdf_available,
    render_pdf,
    summary_from_payload,
)
from soclab.scoring import GATE_NAMES

FIXED = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
PAGE = re.compile(rb"/Type\s*/Page\b(?!s)")


def _normalized(pdf_text: Callable[[bytes], str], data: bytes) -> str:
    return re.sub(r"\s+", " ", pdf_text(data))


@pytest.fixture
def pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("reportlab")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(int(FIXED.timestamp())))


def test_pdf_is_deterministic_and_one_page(clean_scorecard: dict[str, Any], pinned: None) -> None:
    summary = summary_from_payload(clean_scorecard)
    first = render_pdf(summary)
    second = render_pdf(summary_from_payload(clean_scorecard))
    assert first == second
    assert first.startswith(b"%PDF-")
    assert len(PAGE.findall(first)) == 1
    assert b"D:20260905120000" in first
    assert len(first) < 64 * 1024


def test_pdf_text_contains_the_key_fields(
    clean_scorecard: dict[str, Any], pinned: None, pdf_text: Callable[[bytes], str]
) -> None:
    summary = summary_from_payload(clean_scorecard)
    text = _normalized(pdf_text, render_pdf(summary))
    assert "Executive assurance summary" in text
    assert summary.campaign_id in text
    assert "mock-investigator-v1" in text and "Provider mock" in text
    assert "2026-09-05 12:00 UTC" in text
    assert "L4 Act with approval" in text
    assert "No mandatory gate failed" in text
    for gate in GATE_NAMES:
        assert gate.replace("_", " ") in text
    for family in summary.families:
        assert family.family in text
    assert "0 of 3 (0%), 95% interval 0% to 56%" in text
    assert "Baseline to protected" in text and "attack success 67% to 0%" in text
    assert "All 3 audit chains verified" in text
    for head in summary.chain_heads:
        assert head.root_hash is not None and head.root_hash in text
    assert "synthetic scenarios" in text


def test_failed_gate_is_visible(
    failed_scorecard: dict[str, Any], pinned: None, pdf_text: Callable[[bytes], str]
) -> None:
    text = _normalized(pdf_text, render_pdf(summary_from_payload(failed_scorecard)))
    assert "L1 Observe" in text
    assert "Mandatory gate failed: sensitive_data_leakage" in text
    assert "FAIL" in text and "Critical failures ATK-001" in text


def test_many_runs_still_fit_one_page(clean_scorecard: dict[str, Any], pinned: None) -> None:
    summary = summary_from_payload(clean_scorecard)
    heads = tuple(summary.chain_heads[0].model_copy(update={"run_id": f"run-{i:02d}"}) for i in range(40))
    data = render_pdf(summary.model_copy(update={"chain_heads": heads, "sample_count": 40}))
    assert len(PAGE.findall(data)) == 1


def test_missing_extra_raises_the_documented_message(
    clean_scorecard: dict[str, Any], hide_reportlab: None
) -> None:
    assert pdf_available() is False
    with pytest.raises(PdfSupportMissingError) as excinfo:
        render_pdf(summary_from_payload(clean_scorecard))
    assert str(excinfo.value) == PDF_EXTRA_HINT
    assert "uv sync --extra pdf" in PDF_EXTRA_HINT
