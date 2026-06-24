#!/usr/bin/env python3
"""
Render Discovery_Scanner_Findings_Triage.md to a polished PDF that opens
natively anywhere (macOS Preview, browsers, etc.).

Run:  python3 build_pdf.py
"""

import os
import re
import html

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted,
    HRFlowable, KeepTogether,
)

HERE = os.path.dirname(os.path.abspath(__file__))
MD = os.path.join(HERE, "Discovery_Scanner_Findings_Triage.md")
OUT = os.path.join(HERE, "Discovery_Scanner_Findings_Triage.pdf")

NAVY = colors.HexColor("#0B1F3A")
COBALT = colors.HexColor("#1A4DB3")
ACCENT = colors.HexColor("#16829B")
GREY = colors.HexColor("#535A66")
LIGHT = colors.HexColor("#EAF0FA")
LIGHTER = colors.HexColor("#F4F7FC")
CODEBG = colors.HexColor("#11151C")
CODEFG = colors.HexColor("#CFE3D0")

styles = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=styles["Normal"], fontName="Helvetica",
                      fontSize=10, leading=14, spaceAfter=6, textColor=colors.HexColor("#22262C"))
H1 = ParagraphStyle("h1", parent=BODY, fontName="Helvetica-Bold", fontSize=17,
                    leading=21, textColor=COBALT, spaceBefore=16, spaceAfter=4)
H2 = ParagraphStyle("h2", parent=BODY, fontName="Helvetica-Bold", fontSize=13,
                    leading=17, textColor=NAVY, spaceBefore=10, spaceAfter=3)
H3 = ParagraphStyle("h3", parent=BODY, fontName="Helvetica-Bold", fontSize=11.5,
                    leading=15, textColor=ACCENT, spaceBefore=7, spaceAfter=2)
TITLE = ParagraphStyle("title", parent=BODY, fontName="Helvetica-Bold", fontSize=24,
                       leading=28, textColor=NAVY, spaceAfter=4)
SUBTITLE = ParagraphStyle("subtitle", parent=BODY, fontName="Helvetica-Oblique",
                          fontSize=12, leading=16, textColor=GREY, spaceAfter=10)
QUOTE = ParagraphStyle("quote", parent=BODY, leftIndent=8, rightIndent=8,
                       fontName="Helvetica-Oblique", textColor=NAVY,
                       spaceBefore=4, spaceAfter=4, leading=14)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=8.5, leading=11, spaceAfter=0)
CELLH = ParagraphStyle("cellh", parent=CELL, fontName="Helvetica-Bold",
                       textColor=colors.white)
BUL = ParagraphStyle("bul", parent=BODY, leftIndent=14, bulletIndent=2, spaceAfter=2)
NUM = ParagraphStyle("num", parent=BODY, leftIndent=18, bulletIndent=2, spaceAfter=2)


def inline(text):
    """Markdown inline -> reportlab mini-HTML."""
    # protect code spans first
    spans = []

    def stash(m):
        spans.append(m.group(1))
        return f"\x00{len(spans)-1}\x00"

    text = re.sub(r"`([^`]+)`", stash, text)
    text = html.escape(text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)

    def unstash(m):
        code = html.escape(spans[int(m.group(1))])
        return f'<font face="Courier" size="9" color="#B02A2A">{code}</font>'

    text = re.sub(r"\x00(\d+)\x00", unstash, text)
    return text


def parse(md_text):
    lines = md_text.split("\n")
    flow = []
    i = 0
    n = len(lines)

    # ---- title block: first H1 + following *italic* line
    while i < n and not lines[i].startswith("# "):
        i += 1
    if i < n:
        flow.append(Paragraph(inline(lines[i][2:].strip()), TITLE))
        i += 1
        while i < n and lines[i].strip() == "":
            i += 1
        if i < n and lines[i].startswith("*") and lines[i].endswith("*"):
            flow.append(Paragraph(inline(lines[i].strip("*").strip()), SUBTITLE))
            i += 1

    while i < n:
        line = lines[i]
        s = line.strip()

        if s == "":
            i += 1
            continue

        if s == "---":
            flow.append(Spacer(1, 4))
            flow.append(HRFlowable(width="100%", thickness=0.6, color=COBALT))
            flow.append(Spacer(1, 4))
            i += 1
            continue

        if s.startswith("### "):
            flow.append(Paragraph(inline(s[4:]), H3)); i += 1; continue
        if s.startswith("## "):
            flow.append(Paragraph(inline(s[3:]), H2)); i += 1; continue
        if s.startswith("# "):
            flow.append(Paragraph(inline(s[2:]), H1))
            flow.append(HRFlowable(width="100%", thickness=1, color=COBALT,
                                   spaceBefore=1, spaceAfter=6))
            i += 1; continue

        # code fence
        if s.startswith("```"):
            i += 1
            buf = []
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i]); i += 1
            i += 1
            code = "\n".join(buf) if buf else " "
            pre = Preformatted(code, ParagraphStyle(
                "code", fontName="Courier", fontSize=8.2, leading=10.5,
                textColor=CODEFG))
            t = Table([[pre]], colWidths=[6.6 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), CODEBG),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            flow.append(t); flow.append(Spacer(1, 4)); continue

        # blockquote
        if s.startswith(">"):
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip()); i += 1
            txt = " ".join(b for b in buf if b)
            p = Paragraph(inline(txt), QUOTE)
            t = Table([[p]], colWidths=[6.6 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, COBALT),
            ]))
            flow.append(t); flow.append(Spacer(1, 4)); continue

        # table
        if s.startswith("|") and i + 1 < n and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            header = [c.strip() for c in s.strip().strip("|").split("|")]
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            flow.append(build_table(header, rows))
            flow.append(Spacer(1, 4))
            continue

        # bullet list
        if s.startswith("- "):
            while i < n and lines[i].strip().startswith("- "):
                flow.append(Paragraph(inline(lines[i].strip()[2:]), BUL, bulletText="\u2022"))
                i += 1
            continue

        # numbered list
        if re.match(r"^\d+\.\s", s):
            while i < n and re.match(r"^\d+\.\s", lines[i].strip()):
                m = re.match(r"^(\d+)\.\s(.*)", lines[i].strip())
                flow.append(Paragraph(inline(m.group(2)), NUM, bulletText=f"{m.group(1)}."))
                i += 1
            continue

        # plain paragraph (may span until blank)
        buf = [s]
        i += 1
        while i < n and lines[i].strip() != "" and not _is_block_start(lines[i]):
            buf.append(lines[i].strip()); i += 1
        flow.append(Paragraph(inline(" ".join(buf)), BODY))

    return flow


def _is_block_start(line):
    s = line.strip()
    return (s.startswith(("#", ">", "- ", "|", "```")) or s == "---"
            or re.match(r"^\d+\.\s", s) is not None)


def build_table(header, rows):
    ncol = len(header)
    avail = 6.9 * inch
    # weight columns by max content length
    widths_chars = [max([len(header[c])] + [len(r[c]) if c < len(r) else 0 for r in rows])
                    for c in range(ncol)]
    total = sum(widths_chars) or 1
    colw = [max(0.6 * inch, avail * w / total) for w in widths_chars]
    # normalize to fit avail
    scale = avail / sum(colw)
    colw = [w * scale for w in colw]

    data = [[Paragraph(inline(h), CELLH) for h in header]]
    for r in rows:
        cells = []
        for c in range(ncol):
            val = r[c] if c < len(r) else ""
            cells.append(Paragraph(inline(val), CELL))
        data.append(cells)

    t = Table(data, colWidths=colw, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D4E6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for ridx in range(1, len(data)):
        if ridx % 2 == 1:
            style.append(("BACKGROUND", (0, ridx), (-1, ridx), LIGHTER))
    t.setStyle(TableStyle(style))
    return t


def main():
    with open(MD, encoding="utf-8") as f:
        md_text = f.read()
    flow = parse(md_text)
    doc = SimpleDocTemplate(
        OUT, pagesize=letter,
        leftMargin=0.8 * inch, rightMargin=0.8 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title="Discovery Scanner Findings — Daily Triage Workflow",
        author="Discovery Agents / Research",
    )
    doc.build(flow)
    print("Wrote:", OUT)


if __name__ == "__main__":
    main()
