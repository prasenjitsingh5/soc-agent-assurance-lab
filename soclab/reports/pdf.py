"""One-page executive PDF.

reportlab is an optional extra so the core install stays small. The import
happens inside :func:`render_pdf`; a missing package becomes
:class:`PdfSupportMissingError` carrying the exact install command. Output
uses the standard fonts only, so nothing is embedded and the file stays
small. With ``SOURCE_DATE_EPOCH`` set the bytes are identical run to run.
"""

from __future__ import annotations

import html
import io
import os
from typing import Any

from soclab.reports.summary import MAX_CHAIN_HEADS, TITLE, ExecutiveSummary

PDF_EXTRA_HINT = (
    "PDF export needs the optional pdf extra. Install it with: uv sync --extra pdf "
    '(or: pip install "soc-agent-assurance-lab[pdf]").'
)


class PdfSupportMissingError(RuntimeError):
    """reportlab is not installed."""


def pdf_available() -> bool:
    try:
        import reportlab  # noqa: F401
    except ImportError:
        return False
    return True


def _pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def escape(text: str) -> str:
    """Escape for reportlab's paragraph markup, which reads ``&amp;``, ``&lt;`` and ``&gt;``."""
    return html.escape(text, quote=False)


def render_pdf(summary: ExecutiveSummary) -> bytes:  # noqa: PLR0915
    """Render the summary to PDF bytes. One A4 page, tables and text only."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise PdfSupportMissingError(PDF_EXTRA_HINT) from exc

    ink = colors.HexColor("#1a1a1a")
    rule = colors.HexColor("#d9d9d9")
    shade = colors.HexColor("#f4f4f4")
    grey = colors.HexColor("#555555")
    ok = "#106b21"
    bad = "#a11d1d"

    body = ParagraphStyle("body", fontName="Helvetica", fontSize=8.5, leading=11, textColor=ink)
    title = ParagraphStyle("title", parent=body, fontName="Helvetica-Bold", fontSize=15, leading=18)
    heading = ParagraphStyle(
        "heading",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=12,
        spaceBefore=7,
        spaceAfter=2,
    )
    small = ParagraphStyle("small", parent=body, fontSize=7, leading=9, textColor=grey)
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=6.5, leading=8)
    level = ParagraphStyle("level", parent=body, fontName="Helvetica-Bold", fontSize=20, leading=23)

    margin = 16 * mm
    width = A4[0] - 2 * margin

    def grid(rows: list[list[Any]], col_widths: list[float], *, header: bool = False) -> Table:
        table = Table(rows, colWidths=col_widths, hAlign="LEFT")
        commands: list[Any] = [
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("LEADING", (0, 0), (-1, -1), 11),
            ("TEXTCOLOR", (0, 0), (-1, -1), ink),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, rule),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ]
        if header:
            commands.append(("BACKGROUND", (0, 0), (-1, 0), shade))
            commands.append(("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"))
        table.setStyle(TableStyle(commands))
        return table

    def colored(text: str, color: str) -> Paragraph:
        return Paragraph(f'<font color="{color}">{escape(text)}</font>', body)

    n = summary.sample_count
    story: list[Any] = [
        Paragraph(escape(TITLE), title),
        Paragraph("SOC Agent Assurance Lab. Should this agent get operational authority?", small),
        Spacer(1, 4),
    ]

    meta = grid(
        [
            ["Campaign", escape(summary.campaign_id), "Date", escape(summary.date_label)],
            ["Provider", escape(summary.provider), "Model", escape(summary.model)],
            ["Configuration", escape(summary.mode), "Scenario runs", str(n)],
        ],
        [26 * mm, 76 * mm, 26 * mm, width - 128 * mm],
    )
    meta.setStyle(
        TableStyle(
            [("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold")]
        )
    )
    story.append(meta)
    story.append(Spacer(1, 6))

    verdict_color = bad if summary.failed_gates or summary.critical_failures else ok
    decision = Table(
        [
            [Paragraph("Recommended authority level", body)],
            [Paragraph(escape(f"{summary.authority_level} {summary.authority_label}"), level)],
            [colored(summary.decision_statement, verdict_color)],
            [
                Paragraph(
                    f"Composite assurance score <b>{summary.composite:.2f}</b>. "
                    f"Attack success rate <b>{_pct(summary.attack_success_rate)}</b> "
                    f"(95% interval {_pct(summary.attack_success_ci95[0])} to "
                    f"{_pct(summary.attack_success_ci95[1])}).",
                    body,
                )
            ],
        ],
        colWidths=[width],
        hAlign="LEFT",
    )
    decision.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1.5, ink),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    story.append(decision)

    story.append(Paragraph("Mandatory gates", heading))
    gates = list(summary.gates)
    gate_rows: list[list[Any]] = []
    for i in range(0, len(gates), 2):
        row: list[Any] = []
        for gate in gates[i : i + 2]:
            row.append(escape(gate.name.replace("_", " ")))
            row.append(colored("pass", ok) if gate.passed else colored("FAIL", bad))
        while len(row) < 4:
            row.append("")
        gate_rows.append(row)
    quarter = width / 4
    story.append(grid(gate_rows, [quarter * 1.4, quarter * 0.6, quarter * 1.4, quarter * 0.6]))

    story.append(Paragraph("Score families", heading))
    family_rows: list[list[Any]] = [["Family", "Weight", "Score", "Components"]]
    for f in summary.families:
        family_rows.append(
            [
                escape(f.family),
                f"{f.weight:.2f}",
                f"{f.score:.2f}",
                Paragraph(escape("; ".join(f.components)), small),
            ]
        )
    story.append(grid(family_rows, [36 * mm, 14 * mm, 14 * mm, width - 64 * mm], header=True))

    story.append(Paragraph("Attack results", heading))
    attack_rows: list[list[Any]] = [
        [
            "Attack success",
            f"{summary.attack_successes} of {n} ({_pct(summary.attack_success_rate)}), 95% interval "
            f"{_pct(summary.attack_success_ci95[0])} to {_pct(summary.attack_success_ci95[1])}",
        ],
        ["False blocks", f"{summary.false_blocks} of {n} ({_pct(summary.false_block_rate)})"],
        ["Critical failures", escape(", ".join(summary.critical_failures) or "none")],
    ]
    if summary.control_change:
        c = summary.control_change
        attack_rows.append(
            [
                "Baseline to protected",
                f"attack success {_pct(c.baseline_attack_success)} to {_pct(c.protected_attack_success)}, "
                f"composite {c.baseline_composite:.2f} to {c.protected_composite:.2f}",
            ]
        )
    attacks = grid(attack_rows, [40 * mm, width - 40 * mm])
    attacks.setStyle(TableStyle([("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold")]))
    story.append(attacks)

    story.append(Paragraph("Evidence chain", heading))
    heads = list(summary.chain_heads)
    if summary.all_chains_valid:
        story.append(colored(f"All {len(heads)} audit chains verified. Head hashes:", ok))
    else:
        story.append(
            colored("At least one audit chain failed verification. Treat this summary as unsupported.", bad)
        )
    head_rows: list[list[Any]] = [
        [Paragraph(escape(h.run_id), mono), Paragraph(escape(h.root_hash or "no events"), mono)]
        for h in heads[:MAX_CHAIN_HEADS]
    ]
    if head_rows:
        story.append(grid(head_rows, [52 * mm, width - 52 * mm]))
    if len(heads) > MAX_CHAIN_HEADS:
        story.append(
            Paragraph(f"and {len(heads) - MAX_CHAIN_HEADS} more runs; see the technical report.", small)
        )

    story.append(Spacer(1, 6))
    cost = "estimated from list prices" if summary.cost_is_estimated else "provider reported"
    notes = [f"Cost figures are {cost}.", *summary.limitations]
    story.append(Paragraph(escape(" ".join(notes)), small))
    story.append(
        Paragraph(
            escape(
                f"Scoring profile {summary.profile_version}, policy {summary.policy_version}, "
                f"fixture {summary.fixture_version}, prompt {summary.prompt_version}. "
                "Every figure is computed from synthetic scenarios and simulated actions. "
                "Nothing here connects to a production system."
            ),
            small,
        )
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=f"{TITLE}: {summary.campaign_id}",
        author="SOC Agent Assurance Lab",
        subject=f"{summary.provider} / {summary.model}, {summary.mode} configuration",
        creator="soclab report",
        invariant=bool(os.environ.get("SOURCE_DATE_EPOCH", "").strip()),
    )
    doc.build(story)
    return buffer.getvalue()


__all__ = ["PDF_EXTRA_HINT", "PdfSupportMissingError", "pdf_available", "render_pdf"]
