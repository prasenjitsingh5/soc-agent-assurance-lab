"""Executive and technical assurance reports rendered from one evidence record."""

from soclab.reports.generator import GeneratedReport, ReportAudience, ReportGenerator, comparison_table
from soclab.reports.pdf import PDF_EXTRA_HINT, PdfSupportMissingError, pdf_available, render_pdf
from soclab.reports.summary import (
    ExecutiveSummary,
    render_text,
    report_timestamp,
    summary_from_payload,
    summary_from_report,
)

__all__ = [
    "PDF_EXTRA_HINT",
    "ExecutiveSummary",
    "GeneratedReport",
    "PdfSupportMissingError",
    "ReportAudience",
    "ReportGenerator",
    "comparison_table",
    "pdf_available",
    "render_pdf",
    "render_text",
    "report_timestamp",
    "summary_from_payload",
    "summary_from_report",
]
