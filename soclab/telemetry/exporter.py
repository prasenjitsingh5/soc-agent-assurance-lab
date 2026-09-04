"""Exporters over one span shape.

The span follows the OpenInference attribute conventions for LLM spans
(``llm.provider``, ``llm.model_name``, ``llm.token_count.*``, ``input.value``,
``output.value``) so any OpenTelemetry backend that understands OpenInference
can ingest it. The optional adapters write the same span to MLflow or Phoenix
when those libraries are installed and configured. Outages in an adapter are
reported in the receipt and never raised into the control path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from soclab.contracts import CanonicalModelEvent, StrictModel
from soclab.redaction import DEFAULT_PATTERNS, redact_secrets


class ExportReceipt(StrictModel):
    exporter: str
    event_id: str
    accepted: bool
    serialized_payload: str
    error: str | None = None


def to_span(event: CanonicalModelEvent, *, patterns: tuple[str, ...] = DEFAULT_PATTERNS) -> dict[str, Any]:
    """Map a canonical event to an OpenInference-compatible span dictionary, redacted."""
    attributes: dict[str, Any] = {
        "openinference.span.kind": "LLM",
        "llm.provider": event.provider,
        "llm.model_name": event.model,
        "llm.token_count.prompt": event.usage.input_tokens,
        "llm.token_count.completion": event.usage.output_tokens,
        "llm.token_count.total": event.usage.total_tokens,
        "llm.token_count.estimated": event.usage.estimated,
        "llm.cost.estimated_usd": event.estimated_cost_usd,
        "llm.cost.is_estimated": event.cost_is_estimated,
        "llm.finish_reason": event.finish_reason.value,
        "output.value": event.output_text,
        "soclab.incident_id": event.incident_id,
        "soclab.agent_id": event.agent_id,
        "soclab.delegated_user_id": event.delegated_user_id,
        "soclab.proposed_tool": event.proposed_tool,
        "soclab.validated_arguments": event.validated_arguments,
        "soclab.risk_tier": event.risk_tier.value if event.risk_tier else None,
        "soclab.policy_outcome": event.policy_outcome.value if event.policy_outcome else None,
        "soclab.evidence_ids": [e.evidence_id for e in event.evidence_refs],
    }
    span = {
        "name": f"llm.{event.provider}.{event.model}",
        "trace_id": event.trace_id,
        "span_id": str(event.event_id),
        "run_id": str(event.run_id),
        "start_time": event.created_at.isoformat(),
        "latency_ms": event.latency_ms,
        "attributes": attributes,
    }
    redacted: dict[str, Any] = redact_secrets(span, patterns)
    return redacted


class TelemetryExporter(Protocol):
    name: str

    def emit(self, event: CanonicalModelEvent) -> ExportReceipt: ...


class InMemoryExporter:
    """Default for tests and CI. Keeps redacted spans in a list."""

    name = "memory"

    def __init__(self, *, patterns: tuple[str, ...] = DEFAULT_PATTERNS) -> None:
        self._patterns = patterns
        self.spans: list[dict[str, Any]] = []

    def emit(self, event: CanonicalModelEvent) -> ExportReceipt:
        span = to_span(event, patterns=self._patterns)
        self.spans.append(span)
        return ExportReceipt(
            exporter=self.name,
            event_id=str(event.event_id),
            accepted=True,
            serialized_payload=json.dumps(span),
        )


class JsonlFileExporter:
    """Append redacted spans to a JSON Lines file. Good enough for a local run folder."""

    name = "jsonl"

    def __init__(self, path: Path, *, patterns: tuple[str, ...] = DEFAULT_PATTERNS) -> None:
        self._path = path
        self._patterns = patterns

    def emit(self, event: CanonicalModelEvent) -> ExportReceipt:
        span = to_span(event, patterns=self._patterns)
        line = json.dumps(span)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError as exc:
            return ExportReceipt(
                exporter=self.name,
                event_id=str(event.event_id),
                accepted=False,
                serialized_payload=line,
                error=str(exc),
            )
        return ExportReceipt(
            exporter=self.name, event_id=str(event.event_id), accepted=True, serialized_payload=line
        )


class _OptionalAdapter:
    """Base for adapters over optional libraries. Missing library or failure means a rejected receipt."""

    name = "optional"
    dependency = ""

    def __init__(self, *, patterns: tuple[str, ...] = DEFAULT_PATTERNS, sink: Any = None) -> None:
        self._patterns = patterns
        self._sink = sink

    def _send(self, span: dict[str, Any]) -> None:  # pragma: no cover - replaced by subclasses
        raise NotImplementedError

    def emit(self, event: CanonicalModelEvent) -> ExportReceipt:
        span = to_span(event, patterns=self._patterns)
        line = json.dumps(span)
        try:
            self._send(span)
        except Exception as exc:  # noqa: BLE001 - telemetry must never raise into the control path
            return ExportReceipt(
                exporter=self.name,
                event_id=str(event.event_id),
                accepted=False,
                serialized_payload=line,
                error=f"{type(exc).__name__}: {exc}",
            )
        return ExportReceipt(
            exporter=self.name, event_id=str(event.event_id), accepted=True, serialized_payload=line
        )


class MlflowExporter(_OptionalAdapter):
    """Logs each span as an MLflow run tag set and metrics. Requires the ``mlflow`` package."""

    name = "mlflow"
    dependency = "mlflow"

    def _send(self, span: dict[str, Any]) -> None:
        if self._sink is not None:
            self._sink(span)
            return
        import mlflow  # type: ignore[import-not-found]  # optional dependency

        attributes = span["attributes"]
        with mlflow.start_run(run_name=span["name"], nested=True):
            mlflow.set_tags({k: str(v) for k, v in attributes.items() if isinstance(v, str)})
            mlflow.log_metrics(
                {
                    "latency_ms": span["latency_ms"],
                    "tokens_total": attributes["llm.token_count.total"],
                    "cost_estimated_usd": attributes["llm.cost.estimated_usd"] or 0.0,
                }
            )


class PhoenixExporter(_OptionalAdapter):
    """Posts spans to a local Arize Phoenix collector. Requires ``httpx`` only; Phoenix runs separately."""

    name = "phoenix"
    dependency = "phoenix"

    def __init__(
        self,
        *,
        endpoint: str = "http://localhost:6006/v1/spans",
        patterns: tuple[str, ...] = DEFAULT_PATTERNS,
        sink: Any = None,
    ) -> None:
        super().__init__(patterns=patterns, sink=sink)
        self._endpoint = endpoint

    def _send(self, span: dict[str, Any]) -> None:
        if self._sink is not None:
            self._sink(span)
            return
        import httpx

        response = httpx.post(self._endpoint, json=span, timeout=2.0)
        response.raise_for_status()
