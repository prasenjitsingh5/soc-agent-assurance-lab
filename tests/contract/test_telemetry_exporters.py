from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from soclab.contracts import CanonicalModelEvent, FinishReason, TokenUsage
from soclab.telemetry import InMemoryExporter, JsonlFileExporter, MlflowExporter, PhoenixExporter, to_span


@pytest.fixture
def canonical_event() -> CanonicalModelEvent:
    return CanonicalModelEvent(
        trace_id="trace-1",
        run_id=uuid4(),
        incident_id="INC-1001",
        agent_id="soc-investigator",
        delegated_user_id="analyst-1",
        provider="mock",
        model="mock-investigator-v1",
        finish_reason=FinishReason.STOP,
        output_text="token=CANARY-SECRET-001 seen in notes",
        usage=TokenUsage(input_tokens=10, output_tokens=5, estimated=False),
        latency_ms=3,
    )


def test_exporter_redacts_canary_secret(canonical_event: CanonicalModelEvent) -> None:
    exporter = InMemoryExporter()
    receipt = exporter.emit(canonical_event)
    assert receipt.accepted is True
    assert "CANARY-SECRET-001" not in receipt.serialized_payload
    assert "[REDACTED]" in receipt.serialized_payload
    assert exporter.spans[0]["attributes"]["openinference.span.kind"] == "LLM"
    assert exporter.spans[0]["attributes"]["llm.token_count.total"] == 15


def test_span_shape_follows_openinference_conventions(canonical_event: CanonicalModelEvent) -> None:
    span = to_span(canonical_event)
    for key in ("llm.provider", "llm.model_name", "llm.token_count.prompt", "output.value"):
        assert key in span["attributes"]
    assert span["trace_id"] == "trace-1"
    assert span["run_id"] == str(canonical_event.run_id)


def test_jsonl_exporter_writes_and_reports_io_errors(
    tmp_path: Path, canonical_event: CanonicalModelEvent
) -> None:
    path = tmp_path / "spans" / "run.jsonl"
    receipt = JsonlFileExporter(path).emit(canonical_event)
    assert receipt.accepted is True
    assert "[REDACTED]" in path.read_text(encoding="utf-8")
    bad = JsonlFileExporter(tmp_path / "spans" / "run.jsonl" / "not-a-dir.jsonl")
    failed = bad.emit(canonical_event)
    assert failed.accepted is False and failed.error


def test_optional_adapters_never_raise(canonical_event: CanonicalModelEvent) -> None:
    received: list[dict[str, Any]] = []
    ok = MlflowExporter(sink=received.append).emit(canonical_event)
    assert ok.accepted is True and received[0]["attributes"]["llm.provider"] == "mock"

    def boom(span: dict[str, Any]) -> None:
        raise ConnectionError("collector down")

    down = PhoenixExporter(sink=boom).emit(canonical_event)
    assert down.accepted is False
    assert down.error is not None and "ConnectionError" in down.error
    assert "CANARY-SECRET-001" not in down.serialized_payload


def test_phoenix_default_endpoint_failure_is_reported_not_raised(
    canonical_event: CanonicalModelEvent,
) -> None:
    receipt = PhoenixExporter(endpoint="http://127.0.0.1:9/v1/spans").emit(canonical_event)
    assert receipt.accepted is False
