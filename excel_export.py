"""
excel_export.py
Generates a styled Excel workbook from the scan report data.
Sheets:
  1. Dashboard  — summary stats + bar chart + pie chart
  2. Scan History — full table with colour-coded rows
"""

import io
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import (
    Font, PatternFill, Alignment, Border, Side, GradientFill
)
from openpyxl.chart import BarChart, PieChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.utils import get_column_letter


# ── Colour constants ────────────────────────────────────────────────────────
BG_DARK      = "0B1326"
BG_CARD      = "171F33"
BG_HEADER    = "222A3D"
GREEN        = "4BE277"
RED          = "F85149"
AMBER        = "FFBA61"
BLUE         = "58A6FF"
TEXT_MAIN    = "DAE2FD"
TEXT_MUTED   = "8B949E"
WHITE        = "FFFFFF"

COLOR_MAP = {
    "CRITICAL":   "F85149",
    "SUSPICIOUS": "FFBA61",
    "SAFE":       "4BE277",
}
BG_MAP = {
    "CRITICAL":   "3D1515",
    "SUSPICIOUS": "3D2E0A",
    "SAFE":       "0D3320",
}

def _fill(hex_color):
    return PatternFill("solid", fgColor=hex_color)

def _font(bold=False, color=TEXT_MAIN, size=11):
    return Font(bold=bold, color=color, name="Calibri", size=size)

def _border():
    s = Side(style="thin", color="2D3449")
    return Border(left=s, right=s, top=s, bottom=s)

def _center():
    return Alignment(horizontal="center", vertical="center", wrap_text=True)

def _left():
    return Alignment(horizontal="left", vertical="center", wrap_text=True)


def generate_excel(reports: list) -> bytes:
    """
    Takes a list of report dicts and returns the raw bytes of an .xlsx file.
    """
    wb = Workbook()

    # ── Sheet 1: Dashboard ──────────────────────────────────────────────────
    ws_dash = wb.active
    ws_dash.title = "Dashboard"
    ws_dash.sheet_view.showGridLines = False
    ws_dash.column_dimensions["A"].width = 3
    for col in ["B", "C", "D", "E", "F"]:
        ws_dash.column_dimensions[col].width = 22

    total      = len(reports)
    critical   = sum(1 for r in reports if r["status"] == "CRITICAL")
    suspicious = sum(1 for r in reports if r["status"] == "SUSPICIOUS")
    safe       = sum(1 for r in reports if r["status"] == "SAFE")

    # Title
    ws_dash.merge_cells("B1:F1")
    ws_dash.row_dimensions[1].height = 10

    ws_dash.merge_cells("B2:F3")
    title_cell = ws_dash["B2"]
    title_cell.value = "🛡️  CyberShield — Threat Analysis Report"
    title_cell.font  = Font(bold=True, size=18, color=WHITE, name="Calibri")
    title_cell.fill  = _fill(BG_CARD)
    title_cell.alignment = _center()
    ws_dash.row_dimensions[2].height = 28
    ws_dash.row_dimensions[3].height = 20

    # Sub-title
    ws_dash.merge_cells("B4:F4")
    sub = ws_dash["B4"]
    sub.value = f"Exported on {datetime.now().strftime('%d %B %Y, %I:%M %p')}"
    sub.font  = _font(color=TEXT_MUTED, size=10)
    sub.fill  = _fill(BG_CARD)
    sub.alignment = _center()
    ws_dash.row_dimensions[4].height = 16

    ws_dash.row_dimensions[5].height = 10

    # KPI cards — row 6–8
    kpis = [
        ("B", "Total Scans",   total,      BLUE),
        ("C", "🔴 Critical",   critical,   RED),
        ("D", "🟡 Suspicious", suspicious, AMBER),
        ("E", "🟢 Safe",       safe,       GREEN),
    ]
    for col, label, val, color in kpis:
        # Label
        lc = ws_dash[f"{col}6"]
        lc.value = label
        lc.font  = Font(bold=True, size=10, color=color, name="Calibri")
        lc.fill  = _fill(BG_HEADER)
        lc.alignment = _center()
        lc.border = _border()
        ws_dash.row_dimensions[6].height = 20

        # Value
        vc = ws_dash[f"{col}7"]
        vc.value = val
        vc.font  = Font(bold=True, size=22, color=color, name="Calibri")
        vc.fill  = _fill(BG_CARD)
        vc.alignment = _center()
        vc.border = _border()
        ws_dash.row_dimensions[7].height = 36

        # bottom padding
        pc = ws_dash[f"{col}8"]
        pc.fill = _fill(BG_CARD)
        pc.border = _border()
        ws_dash.row_dimensions[8].height = 8

    ws_dash.row_dimensions[9].height = 14

    # Hidden data table for charts (rows 10–13)
    chart_data = [
        ("Status",    "Count"),
        ("Critical",  critical),
        ("Suspicious",suspicious),
        ("Safe",      safe),
    ]
    for i, (label, count) in enumerate(chart_data, start=10):
        ws_dash[f"B{i}"] = label
        ws_dash[f"C{i}"] = count
        ws_dash.row_dimensions[i].height = 0   # hide rows

    # ── Bar Chart ───────────────────────────────────────────────────────────
    bar = BarChart()
    bar.type   = "col"
    bar.title  = "Scan Results by Status"
    bar.style  = 10
    bar.y_axis.title = "Count"
    bar.x_axis.title = "Status"
    bar.width  = 14
    bar.height = 10

    bar_data = Reference(ws_dash, min_col=3, min_row=10, max_row=13)
    bar_cats = Reference(ws_dash, min_col=2, min_row=11, max_row=13)
    bar.add_data(bar_data, titles_from_data=True)
    bar.set_categories(bar_cats)
    bar.series[0].graphicalProperties.solidFill = BLUE
    ws_dash.add_chart(bar, "B10")

    # ── Pie Chart ───────────────────────────────────────────────────────────
    pie = PieChart()
    pie.title  = "Status Distribution"
    pie.style  = 10
    pie.width  = 14
    pie.height = 10

    pie_data = Reference(ws_dash, min_col=3, min_row=10, max_row=13)
    pie_cats = Reference(ws_dash, min_col=2, min_row=11, max_row=13)
    pie.add_data(pie_data, titles_from_data=True)
    pie.set_categories(pie_cats)
    ws_dash.add_chart(pie, "E10")

    # ── Sheet 2: Scan History ───────────────────────────────────────────────
    ws_hist = wb.create_sheet("Scan History")
    ws_hist.sheet_view.showGridLines = False

    col_widths = [6, 14, 40, 15, 14, 16, 14]
    col_headers = ["#", "Tracking ID", "Domain / URL", "Prediction", "Status", "Confidence (%)", "Scan Time"]

    for i, (w, h) in enumerate(zip(col_widths, col_headers), start=1):
        col = get_column_letter(i)
        ws_hist.column_dimensions[col].width = w
        cell = ws_hist.cell(row=1, column=i, value=h)
        cell.font      = Font(bold=True, size=11, color=WHITE, name="Calibri")
        cell.fill      = _fill(BG_HEADER)
        cell.alignment = _center()
        cell.border    = _border()
    ws_hist.row_dimensions[1].height = 22

    for row_idx, report in enumerate(reports, start=2):
        status  = report.get("status", "SAFE")
        fg      = COLOR_MAP.get(status, WHITE)
        bg      = BG_MAP.get(status, BG_CARD)

        row_vals = [
            row_idx - 1,
            report.get("id", ""),
            report.get("domain", ""),
            report.get("prediction", ""),
            status,
            report.get("confidence", 0),
            report.get("time", ""),
        ]

        for col_idx, val in enumerate(row_vals, start=1):
            cell = ws_hist.cell(row=row_idx, column=col_idx, value=val)
            cell.fill      = _fill(bg)
            cell.border    = _border()
            cell.alignment = _center() if col_idx != 3 else _left()

            if col_idx == 5:   # Status column — coloured text
                cell.font = Font(bold=True, color=fg, size=10, name="Calibri")
            elif col_idx == 6: # Confidence
                cell.font = Font(bold=True, color=fg, size=10, name="Calibri")
                cell.number_format = '0.00"%"'
            else:
                cell.font = _font(size=10)

        ws_hist.row_dimensions[row_idx].height = 18

    # Freeze header row
    ws_hist.freeze_panes = "A2"

    # ── Serialise to bytes ──────────────────────────────────────────────────
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()
