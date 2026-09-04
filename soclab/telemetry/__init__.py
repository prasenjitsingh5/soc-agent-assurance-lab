"""Portable telemetry.

Canonical events become OpenInference-style span records. Secrets are redacted
before anything is serialized. An in-memory exporter is the default for CI; the
MLflow and Phoenix adapters are optional and never influence authorization.
"""

from soclab.telemetry.exporter import (
    ExportReceipt,
    InMemoryExporter,
    JsonlFileExporter,
    MlflowExporter,
    PhoenixExporter,
    TelemetryExporter,
    to_span,
)

__all__ = [
    "ExportReceipt",
    "InMemoryExporter",
    "JsonlFileExporter",
    "MlflowExporter",
    "PhoenixExporter",
    "TelemetryExporter",
    "to_span",
]
