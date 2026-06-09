"""
SOC Platform — PDF Report Generation Module
=============================================
Generates professional incident reports in PDF format using ReportLab.

Features:
    - Branded header with dark SOC theme (#1a1a2e / #16213e)
    - Incident details, MITRE ATT&CK mapping, investigation notes table
    - Resolution section and automatic page-number footer
    - Report catalogue via filesystem scan of the reports directory

All functions are self-contained and use the shared DB connection pattern.
"""

from __future__ import annotations

import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Optional

# ReportLab imports
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import HRFlowable

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
DB_PATH: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "database", "soc.db"
)

REPORTS_DIR: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "reports"
)


def _get_conn() -> sqlite3.Connection:
    """Return a new SQLite connection with WAL mode & foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
_DARK_PRIMARY   = colors.HexColor("#1a1a2e")
_DARK_SECONDARY = colors.HexColor("#16213e")
_ACCENT_BLUE    = colors.HexColor("#0f3460")
_ACCENT_RED     = colors.HexColor("#e94560")
_LIGHT_GREY     = colors.HexColor("#f0f0f0")
_WHITE          = colors.white
_BLACK          = colors.black

# ---------------------------------------------------------------------------
# Custom styles
# ---------------------------------------------------------------------------
_BASE_STYLES = getSampleStyleSheet()


def _make_styles() -> dict[str, ParagraphStyle]:
    """Build a dictionary of custom paragraph styles for the report."""
    return {
        "report_title": ParagraphStyle(
            "ReportTitle",
            parent=_BASE_STYLES["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=30,
            textColor=_WHITE,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "report_subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=_BASE_STYLES["Normal"],
            fontName="Helvetica",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#cccccc"),
            alignment=TA_CENTER,
            spaceAfter=2,
        ),
        "report_timestamp": ParagraphStyle(
            "ReportTimestamp",
            parent=_BASE_STYLES["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#aaaaaa"),
            alignment=TA_CENTER,
        ),
        "section_heading": ParagraphStyle(
            "SectionHeading",
            parent=_BASE_STYLES["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=_DARK_PRIMARY,
            spaceBefore=18,
            spaceAfter=8,
            borderPadding=(0, 0, 2, 0),
        ),
        "body": ParagraphStyle(
            "Body",
            parent=_BASE_STYLES["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=_BLACK,
        ),
        "cell": ParagraphStyle(
            "Cell",
            parent=_BASE_STYLES["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=_BLACK,
        ),
        "cell_bold": ParagraphStyle(
            "CellBold",
            parent=_BASE_STYLES["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=_BLACK,
        ),
        "footer": ParagraphStyle(
            "Footer",
            parent=_BASE_STYLES["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#888888"),
            alignment=TA_CENTER,
        ),
    }


# ---------------------------------------------------------------------------
# Footer (page numbers)
# ---------------------------------------------------------------------------

class _PageFooter:
    """Canvas callback that draws a page-number footer on every page."""

    def __init__(self, doc: SimpleDocTemplate) -> None:
        self.doc = doc

    def __call__(self, canvas, doc) -> None:  # noqa: D102
        canvas.saveState()
        page_text = f"Page {doc.page}"
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#888888"))
        canvas.drawCentredString(
            A4[0] / 2,
            15 * mm,
            page_text,
        )
        # Thin rule above footer
        canvas.setStrokeColor(colors.HexColor("#cccccc"))
        canvas.setLineWidth(0.5)
        canvas.line(
            doc.leftMargin,
            20 * mm,
            A4[0] - doc.rightMargin,
            20 * mm,
        )
        canvas.restoreState()


# ---------------------------------------------------------------------------
# Internal builder helpers
# ---------------------------------------------------------------------------

def _build_header_block(
    styles: dict[str, ParagraphStyle],
    incident_id: str,
    generated_at: str,
) -> list:
    """Return flowables for the dark-themed report header."""
    # We simulate a coloured banner via a single-cell table with a dark bg.
    title_para = Paragraph("SOC Incident Report", styles["report_title"])
    subtitle_para = Paragraph(incident_id, styles["report_subtitle"])
    ts_para = Paragraph(f"Generated: {generated_at}", styles["report_timestamp"])

    banner_table = Table(
        [[title_para], [subtitle_para], [ts_para]],
        colWidths=[A4[0] - 2 * inch],
    )
    banner_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _DARK_PRIMARY),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, 0), 20),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 16),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ])
    )
    return [banner_table, Spacer(1, 16)]


def _build_details_table(
    styles: dict[str, ParagraphStyle],
    incident: dict,
) -> list:
    """Return the "Incident Details" section flowables."""
    fields = [
        ("Incident ID",  incident.get("incident_id", "—")),
        ("Alert ID",     incident.get("alert_id", "—")),
        ("Threat Type",  incident.get("threat_type", "—")),
        ("Severity",     incident.get("severity", "—")),
        ("Status",       incident.get("status", "—")),
        ("Created By",   incident.get("created_by", "—")),
        ("Created At",   incident.get("created_at", "—")),
        ("Updated At",   incident.get("updated_at", "—") or "—"),
    ]

    data = [
        [
            Paragraph(label, styles["cell_bold"]),
            Paragraph(str(value), styles["cell"]),
        ]
        for label, value in fields
    ]

    table = Table(data, colWidths=[1.8 * inch, 4.5 * inch])
    table.setStyle(
        TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), _LIGHT_GREY),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ])
    )

    return [
        Paragraph("Incident Details", styles["section_heading"]),
        HRFlowable(width="100%", thickness=1, color=_DARK_SECONDARY, spaceAfter=8),
        table,
        Spacer(1, 10),
    ]


def _build_mitre_section(
    styles: dict[str, ParagraphStyle],
    alert: dict | None,
) -> list:
    """Return the MITRE ATT&CK mapping section."""
    if alert is None:
        return [
            Paragraph("MITRE ATT&CK Mapping", styles["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=_DARK_SECONDARY, spaceAfter=8),
            Paragraph("<i>No linked alert found — MITRE data unavailable.</i>", styles["body"]),
            Spacer(1, 10),
        ]

    fields = [
        ("Tactic",         alert.get("mitre_tactic", "—") or "—"),
        ("Technique ID",   alert.get("mitre_technique_id", "—") or "—"),
        ("Technique Name", alert.get("mitre_technique_name", "—") or "—"),
    ]

    data = [
        [
            Paragraph(label, styles["cell_bold"]),
            Paragraph(str(value), styles["cell"]),
        ]
        for label, value in fields
    ]

    table = Table(data, colWidths=[1.8 * inch, 4.5 * inch])
    table.setStyle(
        TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), _LIGHT_GREY),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ])
    )

    return [
        Paragraph("MITRE ATT&CK Mapping", styles["section_heading"]),
        HRFlowable(width="100%", thickness=1, color=_DARK_SECONDARY, spaceAfter=8),
        table,
        Spacer(1, 10),
    ]


def _build_description_section(
    styles: dict[str, ParagraphStyle],
    description: str,
) -> list:
    """Return the description section flowables."""
    return [
        Paragraph("Description", styles["section_heading"]),
        HRFlowable(width="100%", thickness=1, color=_DARK_SECONDARY, spaceAfter=8),
        Paragraph(description or "<i>No description provided.</i>", styles["body"]),
        Spacer(1, 10),
    ]


def _build_notes_section(
    styles: dict[str, ParagraphStyle],
    notes: list[dict],
) -> list:
    """Return the investigation-notes table section."""
    elements: list = [
        Paragraph("Investigation Notes", styles["section_heading"]),
        HRFlowable(width="100%", thickness=1, color=_DARK_SECONDARY, spaceAfter=8),
    ]

    if not notes:
        elements.append(
            Paragraph("<i>No investigation notes recorded.</i>", styles["body"])
        )
        elements.append(Spacer(1, 10))
        return elements

    # Table header
    header = [
        Paragraph("Analyst", styles["cell_bold"]),
        Paragraph("Note", styles["cell_bold"]),
        Paragraph("Verdict", styles["cell_bold"]),
        Paragraph("Created At", styles["cell_bold"]),
    ]
    data = [header]

    for n in notes:
        data.append([
            Paragraph(str(n.get("analyst", "—")), styles["cell"]),
            Paragraph(str(n.get("note", "—")), styles["cell"]),
            Paragraph(str(n.get("verdict", "—") or "—"), styles["cell"]),
            Paragraph(str(n.get("created_at", "—")), styles["cell"]),
        ])

    table = Table(data, colWidths=[1.1 * inch, 3.0 * inch, 1.2 * inch, 1.0 * inch])
    table.setStyle(
        TableStyle([
            # Header row
            ("BACKGROUND",    (0, 0), (-1, 0), _DARK_SECONDARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), _WHITE),
            # Alternating body rows
            *[
                ("BACKGROUND", (0, i), (-1, i), _LIGHT_GREY)
                for i in range(2, len(data), 2)
            ],
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ])
    )

    elements.append(table)
    elements.append(Spacer(1, 10))
    return elements


def _build_resolution_section(
    styles: dict[str, ParagraphStyle],
    resolution_notes: str | None,
) -> list:
    """Return the resolution section flowables."""
    return [
        Paragraph("Resolution", styles["section_heading"]),
        HRFlowable(width="100%", thickness=1, color=_DARK_SECONDARY, spaceAfter=8),
        Paragraph(
            resolution_notes if resolution_notes else "<i>Incident not yet resolved.</i>",
            styles["body"],
        ),
        Spacer(1, 10),
    ]


# ---------------------------------------------------------------------------
# 1. generate_incident_report
# ---------------------------------------------------------------------------

def generate_incident_report(incident_id: str) -> str:
    """Generate a professional PDF report for the given incident.

    The report is saved to::

        j:/Notes/New folder/soc/reports/incident_{incident_id}_{timestamp}.pdf

    Sections included:
        1. Header banner with title, incident ID, generation timestamp
        2. Incident Details (ID, Alert ID, Threat Type, Severity, …)
        3. MITRE ATT&CK Mapping (from the linked alert)
        4. Description
        5. Investigation Notes (tabular)
        6. Resolution notes
        7. Page-number footer on every page

    Args:
        incident_id: The incident to report on (e.g. ``INC001``).

    Returns:
        The absolute file path of the generated PDF.

    Raises:
        ValueError: If the incident does not exist.
    """
    conn = _get_conn()
    try:
        # ── Fetch data ────────────────────────────────────────────────
        incident_row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id.upper(),),
        ).fetchone()

        if incident_row is None:
            raise ValueError(f"Incident '{incident_id}' not found in database.")

        incident = dict(incident_row)
        alert_id = incident.get("alert_id")

        # Linked alert (for MITRE mapping)
        alert: dict | None = None
        if alert_id:
            alert_row = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            alert = dict(alert_row) if alert_row else None

        # Investigation notes
        notes_rows = conn.execute(
            "SELECT * FROM investigation_notes WHERE alert_id = ? ORDER BY created_at ASC",
            (alert_id or "",),
        ).fetchall()
        notes = [dict(r) for r in notes_rows]

    finally:
        conn.close()

    # ── Prepare output path ───────────────────────────────────────────
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts_stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"incident_{incident_id.upper()}_{ts_stamp}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    # ── Build the document ────────────────────────────────────────────
    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        topMargin=0.6 * inch,
        bottomMargin=0.8 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        title=f"SOC Incident Report — {incident_id.upper()}",
        author="SOC Platform",
    )

    styles = _make_styles()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story: list = []

    # Header
    story.extend(_build_header_block(styles, incident_id.upper(), generated_at))

    # Incident Details
    story.extend(_build_details_table(styles, incident))

    # MITRE ATT&CK
    story.extend(_build_mitre_section(styles, alert))

    # Description
    story.extend(_build_description_section(styles, incident.get("description", "")))

    # Investigation Notes
    story.extend(_build_notes_section(styles, notes))

    # Resolution
    story.extend(_build_resolution_section(styles, incident.get("resolution_notes")))

    # Build PDF with footer
    footer_handler = _PageFooter(doc)
    doc.build(
        story,
        onFirstPage=footer_handler,
        onLaterPages=footer_handler,
    )

    return os.path.abspath(filepath)


# ---------------------------------------------------------------------------
# 2. get_generated_reports
# ---------------------------------------------------------------------------

# Regex to extract incident ID and timestamp from our filename pattern:
#   incident_INC001_20260609_153045.pdf
_REPORT_FILENAME_RE = re.compile(
    r"^incident_(?P<incident_id>INC\d+)_(?P<ts>\d{8}_\d{6})\.pdf$",
    re.IGNORECASE,
)


def get_generated_reports() -> list[dict]:
    """Scan the reports directory and return metadata for each generated PDF.

    Returns:
        A list of dicts, each containing:

        - ``filename``    – The PDF file name.
        - ``incident_id`` – Extracted incident ID (e.g. ``INC001``).
        - ``generated_at`` – Timestamp string (``YYYY-MM-DD HH:MM:SS``).
        - ``filepath``    – Absolute path to the PDF.

        The list is sorted newest-first by ``generated_at``.
    """
    if not os.path.isdir(REPORTS_DIR):
        return []

    reports: list[dict] = []

    for entry in os.scandir(REPORTS_DIR):
        if not entry.is_file() or not entry.name.lower().endswith(".pdf"):
            continue

        match = _REPORT_FILENAME_RE.match(entry.name)
        if match:
            raw_ts = match.group("ts")  # e.g. 20260609_153045
            try:
                generated_dt = datetime.strptime(raw_ts, "%Y%m%d_%H%M%S")
                generated_str = generated_dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                generated_str = raw_ts

            reports.append({
                "filename":     entry.name,
                "incident_id":  match.group("incident_id").upper(),
                "generated_at": generated_str,
                "filepath":     os.path.abspath(entry.path),
            })
        else:
            # Non-standard filename — still include with best-effort metadata
            stat = entry.stat()
            reports.append({
                "filename":     entry.name,
                "incident_id":  "UNKNOWN",
                "generated_at": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "filepath":     os.path.abspath(entry.path),
            })

    # Sort newest first
    reports.sort(key=lambda r: r["generated_at"], reverse=True)
    return reports
