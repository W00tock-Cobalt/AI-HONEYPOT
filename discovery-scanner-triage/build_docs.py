#!/usr/bin/env python3
"""
Generates the Discovery Scanner Findings deliverable as a Word (.docx) document:

  1. Discovery_Scanner_Findings_Triage.docx

A polished, shareable runbook that captures the team's request:
"come in each morning, look at the list of successful scans, and review the
scanner findings produced" — plus the dashboard we eventually want.

Run:  python3 build_docs.py
"""

import os
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- palette
NAVY = RGBColor(0x0B, 0x1F, 0x3A)
COBALT = RGBColor(0x1A, 0x4D, 0xB3)
ACCENT = RGBColor(0x16, 0x82, 0x9B)
GREY = RGBColor(0x53, 0x5A, 0x66)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
GREEN = RGBColor(0x1B, 0x7A, 0x3D)
RED = RGBColor(0xB0, 0x2A, 0x2A)
AMBER = RGBColor(0x9A, 0x6A, 0x00)
LIGHT = "EAF0FA"
LIGHTER = "F4F7FC"
CODE_FILL = "11151C"
HEADER_FILL = "0B1F3A"
BAND_FILL = "1A4DB3"


# ---------------------------------------------------------------- helpers
def set_cell_bg(cell, hex_color):
    tcpr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcpr.append(shd)


def set_cell_margins(cell, top=60, bottom=60, left=100, right=100):
    tcpr = cell._tc.get_or_add_tcPr()
    m = OxmlElement("w:tcMar")
    for tag, val in (("top", top), ("bottom", bottom), ("start", left), ("end", right)):
        node = OxmlElement(f"w:{tag}")
        node.set(qn("w:w"), str(val))
        node.set(qn("w:type"), "dxa")
        m.append(node)
    tcpr.append(m)


def style_base(doc):
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10.5)
    style.font.color.rgb = RGBColor(0x22, 0x26, 0x2C)
    pf = style.paragraph_format
    pf.space_after = Pt(6)
    pf.line_spacing = 1.12


def add_run(p, text, size=10.5, bold=False, italic=False, color=None, font="Calibri"):
    r = p.add_run(text)
    r.font.name = font
    r.font.size = Pt(size)
    r.bold = bold
    r.italic = italic
    if color is not None:
        r.font.color.rgb = color
    return r


def h1(doc, text, color=COBALT):
    p = doc.add_paragraph()
    add_run(p, text, size=16, bold=True, color=color)
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(4)
    pPr = p._p.get_or_add_pPr()
    pbdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "10")
    bottom.set(qn("w:space"), "4")
    bottom.set(qn("w:color"), "1A4DB3")
    pbdr.append(bottom)
    pPr.append(pbdr)
    return p


def h2(doc, text, color=NAVY):
    p = doc.add_paragraph()
    add_run(p, text, size=13, bold=True, color=color)
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(3)
    return p


def h3(doc, text, color=ACCENT):
    p = doc.add_paragraph()
    add_run(p, text, size=11.5, bold=True, color=color)
    p.paragraph_format.space_before = Pt(7)
    p.paragraph_format.space_after = Pt(2)
    return p


def para(doc, text, size=10.5, italic=False, color=None, after=6):
    p = doc.add_paragraph()
    add_run(p, text, size=size, italic=italic, color=color)
    p.paragraph_format.space_after = Pt(after)
    return p


def bullet(doc, text, level=0, bold_lead=None):
    p = doc.add_paragraph(style="List Bullet" if level == 0 else "List Bullet 2")
    if bold_lead:
        add_run(p, bold_lead, bold=True)
        add_run(p, text)
    else:
        add_run(p, text)
    p.paragraph_format.space_after = Pt(2)
    return p


def numbered(doc, text, bold_lead=None):
    p = doc.add_paragraph(style="List Number")
    if bold_lead:
        add_run(p, bold_lead, bold=True)
        add_run(p, text)
    else:
        add_run(p, text)
    p.paragraph_format.space_after = Pt(2)
    return p


def callout(doc, text, fill=LIGHT, color=NAVY, lead=None):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.rows[0].cells[0]
    set_cell_bg(cell, fill)
    set_cell_margins(cell, top=120, bottom=120, left=160, right=160)
    cell.paragraphs[0].text = ""
    if lead:
        add_run(cell.paragraphs[0], lead, size=10.5, bold=True, color=color)
    add_run(cell.paragraphs[0], text, size=10.5, italic=True, color=color)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return tbl


def code_block(doc, lines, font_size=8.5):
    """Monospace, dark-filled block for log / JSON snippets."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.style = "Table Grid"
    cell = tbl.rows[0].cells[0]
    set_cell_bg(cell, CODE_FILL)
    set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
    if isinstance(lines, str):
        lines = lines.split("\n")
    for i, line in enumerate(lines):
        p = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.0
        add_run(p, line if line else " ", size=font_size,
                color=RGBColor(0xCF, 0xE3, 0xD0), font="Consolas")
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return tbl


def make_table(doc, headers, rows, widths=None, header_fill=HEADER_FILL,
               band=True, font_size=9.5, header_size=9.5, bold_first=True):
    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.style = "Table Grid"
    hdr = tbl.rows[0].cells
    for i, htext in enumerate(headers):
        set_cell_bg(hdr[i], header_fill)
        set_cell_margins(hdr[i])
        hdr[i].paragraphs[0].text = ""
        add_run(hdr[i].paragraphs[0], htext, size=header_size, bold=True, color=WHITE)
    for ridx, row in enumerate(rows):
        cells = tbl.add_row().cells
        fill = LIGHTER if (band and ridx % 2 == 0) else None
        for cidx, val in enumerate(row):
            set_cell_margins(cells[cidx])
            if fill:
                set_cell_bg(cells[cidx], fill)
            cells[cidx].paragraphs[0].text = ""
            parts = str(val).split("\n")
            for pi, part in enumerate(parts):
                pgr = cells[cidx].paragraphs[0] if pi == 0 else cells[cidx].add_paragraph()
                bold = bold_first and cidx == 0
                add_run(pgr, part, size=font_size, bold=bold)
                pgr.paragraph_format.space_after = Pt(0)
    if widths:
        for col_idx, w in enumerate(widths):
            for cell in tbl.columns[col_idx].cells:
                cell.width = Inches(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return tbl


def kpi_row(doc, tiles):
    """A row of metric tiles: list of (label, value)."""
    tbl = doc.add_table(rows=2, cols=len(tiles))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.style = "Table Grid"
    for i, (label, value) in enumerate(tiles):
        top = tbl.rows[0].cells[i]
        bot = tbl.rows[1].cells[i]
        set_cell_bg(top, LIGHTER)
        set_cell_bg(bot, "FFFFFF")
        set_cell_margins(top, top=80, bottom=20, left=100, right=100)
        set_cell_margins(bot, top=10, bottom=80, left=100, right=100)
        top.paragraphs[0].text = ""
        bot.paragraphs[0].text = ""
        add_run(top.paragraphs[0], label, size=8, color=GREY)
        add_run(bot.paragraphs[0], value, size=15, bold=True, color=COBALT)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return tbl


def cover(doc, title, subtitle, meta_lines):
    for _ in range(3):
        doc.add_paragraph()
    band = doc.add_table(rows=1, cols=1)
    band.alignment = WD_TABLE_ALIGNMENT.CENTER
    c = band.rows[0].cells[0]
    set_cell_bg(c, BAND_FILL)
    set_cell_margins(c, top=300, bottom=300, left=240, right=240)
    c.paragraphs[0].text = ""
    add_run(c.paragraphs[0], "DISCOVERY AGENTS", size=13, bold=True, color=WHITE)
    tp = c.add_paragraph()
    add_run(tp, title, size=26, bold=True, color=WHITE)
    sp = c.add_paragraph()
    add_run(sp, subtitle, size=13, italic=True, color=RGBColor(0xD7, 0xE2, 0xF6))
    doc.add_paragraph()
    for label, value in meta_lines:
        p = doc.add_paragraph()
        add_run(p, f"{label}:  ", bold=True, color=NAVY)
        add_run(p, value, color=GREY)
        p.paragraph_format.space_after = Pt(2)
    doc.add_page_break()


def page_break(doc):
    doc.add_page_break()


# ================================================================
# DOCUMENT — DAILY SCANNER FINDINGS TRIAGE
# ================================================================
def build_doc():
    doc = Document()
    style_base(doc)
    sec = doc.sections[0]
    sec.left_margin = Inches(0.9)
    sec.right_margin = Inches(0.9)
    sec.top_margin = Inches(0.8)
    sec.bottom_margin = Inches(0.8)

    cover(
        doc,
        "Scanner Findings Triage",
        "A daily workflow for reviewing automated discovery-scan output \u2014 "
        "and the dashboard we want next",
        [
            ("Document", "Discovery Scanner Findings \u2014 Daily Triage Workflow"),
            ("Audience", "Research team / Core testers covering triage"),
            ("Owner", "Discovery Agents / Research"),
            ("Status", "Working draft \u2014 process proposal"),
        ],
    )

    # ---------------------------------------------------------------- 1
    h1(doc, "1. Purpose & The Ask")
    para(doc,
         "Discovery agents run automated security scanners against client targets on a fixed "
         "schedule. Scans kick off at midnight on the day a test starts, and we do not know which "
         "of them will actually succeed until they have finished running. With only a small number "
         "of testers actively triaging output, a lot of completed scan results currently sit "
         "unreviewed.")
    para(doc,
         "The ask is simple and low-cost: any morning, a researcher can open the list of scans, "
         "look at the ones that completed successfully, and read through the scanner findings they "
         "produced. You do not need to be assigned to the pentest, and you do not need to take "
         "formal action. The goal is a quick, informed pass over fresh output so that real issues "
         "surface faster and obvious noise is flagged for whoever owns the engagement.")
    callout(doc,
            "do not formally reject or accept findings during this pass. Read the output, sanity-"
            "check it, and record a non-binding assessment for the tester who owns the engagement. "
            "Accept/reject decisions stay with the assigned tester.",
            lead="Guardrail \u2014 ")

    h2(doc, "What this document covers")
    bullet(doc, "How scans run and why triage is reactive (Section 2).")
    bullet(doc, "The step-by-step morning triage workflow (Section 3).")
    bullet(doc, "The tools and sites in scope and how to think about coverage (Section 4).")
    bullet(doc, "Reading a scan log to tell success from failure \u2014 worked example (Section 5).")
    bullet(doc, "Anatomy of a single scanner finding \u2014 worked example (Section 6).")
    bullet(doc, "A non-binding assessment rubric (Section 7).")
    bullet(doc, "The dashboard we want eventually (Section 8).")

    # ---------------------------------------------------------------- 2
    h1(doc, "2. How Discovery Scans Run")
    para(doc,
         "Each scan is a scheduled, automated job tied to a pentest. The scheduler launches the "
         "configured tools at midnight on the engagement's start day, and the jobs run "
         "unattended to completion (or failure). Because they run overnight and unattended, the "
         "first time anyone knows whether a scan produced usable output is the next morning \u2014 "
         "which is exactly the window this workflow targets.")
    para(doc, "A scan moves through a small set of states:")
    make_table(
        doc,
        ["Status", "Meaning", "Triage action"],
        [
            ["Completed", "The job finished and produced output / findings.",
             "Primary target for review \u2014 read the findings."],
            ["Failed", "The job exited with an error before finishing.",
             "Usually skip; note repeat failures (may still hold partial passive output)."],
            ["In progress", "The job is still running.",
             "Leave it; re-check later in the day."],
        ],
        widths=[1.2, 3.4, 2.6],
    )
    callout(doc,
            "Treat the scan list as a worklist, not a guarantee. Roughly a third of scans fail on "
            "any given morning (timeouts, scope/context errors, target down). Sort to the "
            "Completed scans first \u2014 that is where the findings are.")

    # ---------------------------------------------------------------- 3
    h1(doc, "3. The Morning Triage Workflow")
    para(doc,
         "A full pass over a morning's successful scans should take well under an hour. Work the "
         "list top to bottom and keep notes as you go.")

    h3(doc, "Step 1 \u2014 Open the list and filter to fresh, successful scans")
    numbered(doc, "Open the scans dashboard and set the date filter to today (or the morning you are reviewing).")
    numbered(doc, "Filter / sort by Status = Completed. These are the scans that produced output.")
    numbered(doc, "Optionally narrow by Tool or by site if you only want to cover one area.")

    h3(doc, "Step 2 \u2014 Open each completed scan's output")
    numbered(doc, "For each completed scan, open its findings (and, when present, the raw tool log / report artifact).")
    numbered(doc, "Note the tool, the target site, and how many findings were produced.")

    h3(doc, "Step 3 \u2014 Read and sanity-check each finding")
    numbered(doc, "Confirm the affected target is actually in scope for the engagement.")
    numbered(doc, "Check that the evidence backs the claim (e.g., the version string or response the tool cites is really present).")
    numbered(doc, "Decide whether it looks real and impactful, needs hands-on verification, or is likely informational / noise.")

    h3(doc, "Step 4 \u2014 Record a non-binding assessment")
    numbered(doc, "Tag each finding with one of the assessment buckets in Section 7.")
    numbered(doc, "Write one or two lines of reasoning \u2014 enough for the assigned tester to act on quickly.")
    numbered(doc, "Do not click accept or reject. That decision stays with the engagement owner.")

    h3(doc, "Step 5 \u2014 Hand off")
    numbered(doc, "Leave your notes where the assigned tester will see them, or flag anything that looks high-impact.")
    numbered(doc, "Move on to the next completed scan.")

    callout(doc,
            "Output of the pass: a short, per-finding note (\u201Clikely valid / verify / noise\u201D + one line) "
            "for the morning's completed scans. Nothing is formally triaged \u2014 you have just made the "
            "owner's job faster.")

    # ---------------------------------------------------------------- 4
    page_break(doc)
    h1(doc, "4. Tools & Sites In Scope")
    para(doc,
         "Discovery currently centers on three main scanning tools running against three main "
         "sites. Knowing what each tool is good (and bad) at tells you how much weight to give a "
         "finding before a human has looked at it.")

    h2(doc, "The three tools")
    make_table(
        doc,
        ["Tool", "Category", "What it produces", "How much to trust unverified"],
        [
            ["ZAP", "Vulnerability (DAST)",
             "Spiders the app, runs passive + active web checks, retire.js library checks; "
             "exports a SARIF report.",
             "Passive findings are reliable signal; active findings vary \u2014 verify impact."],
            ["Nuclei", "Vulnerability (templates)",
             "Matches targets against community/templated CVE & misconfig signatures.",
             "High-confidence when a template matches exactly; watch for version-only matches."],
            ["ffuf", "Reconnaissance (fuzzing)",
             "Content / directory discovery \u2014 enumerates paths, params, vhosts.",
             "Recon, not vulns \u2014 use it to understand surface, confirm interesting hits."],
        ],
        widths=[0.9, 1.5, 2.7, 2.3],
        font_size=9,
    )
    para(doc,
         "A recon-consolidation data-processor step also runs to merge discovered URLs into the "
         "input list the scanners consume (for example, the consolidated_urls.txt that ZAP "
         "imports). It is plumbing, not a findings source.", italic=True, color=GREY, size=9)

    h2(doc, "The three sites")
    make_table(
        doc,
        ["Site", "Role", "Notes for triage"],
        [
            ["app.petquant.com", "Primary web application",
             "Main user-facing app; expect the bulk of web findings."],
            ["api.petquant.com", "API surface",
             "Endpoint/auth findings; cross-check against the app's behavior."],
            ["staging-portal.givingafoundation.app", "Staging portal",
             "Non-production; weigh impact accordingly (isolation from prod data)."],
        ],
        widths=[2.8, 1.7, 2.7],
        font_size=9,
    )

    h2(doc, "Coverage at a glance")
    make_table(
        doc,
        ["Site \\ Tool", "ZAP", "Nuclei", "ffuf"],
        [
            ["app.petquant.com", "Vuln scan", "Vuln scan", "Recon"],
            ["api.petquant.com", "Vuln scan", "Vuln scan", "Recon"],
            ["staging-portal.givingafoundation.app", "Vuln scan", "Vuln scan", "Recon"],
        ],
        widths=[3.0, 1.4, 1.4, 1.4],
        font_size=9,
    )
    para(doc,
         "Use the matrix to spot gaps: if a site has no Completed scan for a given tool this "
         "morning, that is a coverage hole to note (often the result of a failed overnight run).",
         italic=True, color=GREY, size=9)

    # ---------------------------------------------------------------- 5
    page_break(doc)
    h1(doc, "5. Reading a Scan Log \u2014 Worked Example (ZAP)")
    para(doc,
         "Before trusting a scan's findings, confirm the scan actually did what it was supposed "
         "to. Tool logs make this quick. Below is an annotated walk-through of a real ZAP run "
         "against app.petquant.com.")

    h2(doc, "Startup \u2014 confirm the tool and rule set loaded")
    code_block(doc, [
        "INFO CommandLineBootstrap - ZAP 2.17.0 started 24/06/2026, 12:16:08 ...",
        "INFO ScanRuleManager - Loaded passive scan rule:",
        "        Vulnerable JS Library (Powered by Retire.js)",
    ])
    para(doc,
         "This tells you the engine version and that the retire.js passive rule is active \u2014 the "
         "rule that produces the \u201CVulnerable JS Library\u201D finding examined in Section 6.")

    h2(doc, "Jobs \u2014 see what ran and what it targeted")
    code_block(doc, [
        "INFO CommandLine - Job import set fileName = /tool/consolidated_urls.txt",
        "INFO CommandLine - Job Report set template = sarif-json",
        "INFO CommandLine - Job Report set reportFile =",
        "        zap-report-app.petquant.com-2026-06-24.sarif.json",
        "INFO CommandLine - Job General spider found 8 URLs",
    ])
    para(doc,
         "The spider seeded from the consolidated URL list and discovered 8 URLs, and the run is "
         "configured to emit a SARIF report. So far, so good.")

    h2(doc, "The failure \u2014 why this scan shows as \u201CFailed\u201D")
    code_block(doc, [
        "ERROR ExtensionAutomation - The starting URI does not belong",
        "        to the context: https://app.petquant.com",
        "INFO  CommandLine - Automation plan failures:",
        "INFO  Control - Automation Framework setting exit status to 1",
        "        due to plan errors",
    ])
    para(doc,
         "The Ajax Spider job failed with a context/scope error, which set the overall exit status "
         "to 1 \u2014 so the orchestrator marks the scan Failed even though the traditional spider and "
         "passive scan ran first. Two takeaways:")
    bullet(doc, "A Failed status is often a scope/context or timeout problem, not a target being secure.",
           bold_lead="Failed \u2260 clean: ")
    bullet(doc, "Earlier jobs (spider, passive/retire.js) may still have produced partial output worth a glance, "
                "but for the morning pass, prioritize cleanly Completed scans first.",
           bold_lead="Partial data: ")
    callout(doc,
            "Quick log checklist: (1) did the expected tool/version start? (2) did the spider/import find "
            "URLs? (3) what is the final exit status / were there plan failures? (4) was the report artifact "
            "written? Answering these takes seconds and tells you how much to trust the output.")

    # ---------------------------------------------------------------- 6
    page_break(doc)
    h1(doc, "6. Anatomy of a Scanner Finding \u2014 Worked Example")
    para(doc,
         "This is a real finding produced by ZAP's retire.js passive rule and written up on the "
         "engagement. Use it as a model for what \u201Cgood\u201D scanner output looks like and what to "
         "check when you read one.")

    h2(doc, "Vulnerable JS Library \u2014 Outdated Next.js")
    make_table(
        doc,
        ["Field", "Value"],
        [
            ["Title", "Vulnerable JS Library (Outdated Software Version)"],
            ["Vulnerability type", "Components with Known Vulnerabilities > Outdated Software Version"],
            ["CWE", "CWE-1395: Dependency on Vulnerable Third-Party Component"],
            ["OWASP severity", "Low  (Likelihood 2/5, Business Impact 2/5)"],
            ["Affected target", "https://staging-portal.givingafoundation.app"],
            ["Affected resource", "/_next/static/chunks/main-6efffc813d6db951.js"],
            ["Detected version", "Next.js 15.5.12"],
            ["Source", "ZAP passive rule \u2014 Vulnerable JS Library (Powered by Retire.js)"],
        ],
        widths=[1.7, 5.5],
        font_size=9,
        bold_first=True,
    )

    h3(doc, "Description")
    para(doc,
         "The application bundles an outdated version of the Next.js framework (15.5.12), which is "
         "subject to multiple published CVEs. The version string is observable directly in the "
         "client-side JavaScript bundle. Because the issue is a dependency on a vulnerable "
         "third-party component (CWE-1395), exact exploitability depends on how the framework is "
         "used in the app.")

    h3(doc, "Associated CVEs")
    make_table(
        doc,
        ["CVEs cited by the finding"],
        [
            ["CVE-2026-44580, CVE-2026-44581, CVE-2026-44582, CVE-2026-45109, CVE-2026-44576"],
            ["CVE-2026-29057, CVE-2026-44577, CVE-2026-44578, CVE-2026-44579, CVE-2026-44572"],
            ["CVE-2026-27980, CVE-2026-44573, CVE-2026-44574, CVE-2026-44575"],
        ],
        widths=[7.2],
        font_size=9,
        bold_first=False,
        band=True,
    )

    h3(doc, "Proof of concept")
    para(doc, "Retrieve the bundle and observe the embedded version string:")
    code_block(doc, [
        "GET /_next/static/chunks/main-6efffc813d6db951.js HTTP/1.1",
        "Host: staging-portal.givingafoundation.app",
        "",
        "HTTP/1.1 200 OK",
        "Content-Type: application/javascript; charset=UTF-8",
        "...",
        "let H = \"15.5.12\";   // Next.js version embedded in the bundle",
    ])

    h3(doc, "Suggested fix (as written on the finding)")
    bullet(doc, "Upgrade Next.js to a patched release \u2014 latest 15.x (e.g. 15.5.18+) or 16.x (e.g. 16.2.6).")
    bullet(doc, "Run npm install / npm audit after the bump and regression-test auth (@auth0/nextjs-auth0) and SSR paths.")
    bullet(doc, "Longer term: SBOM generation, automated dependency monitoring (Dependabot/Renovate/Snyk), and lockfile pinning.")

    # ---------------------------------------------------------------- 7
    h1(doc, "7. Assessing a Finding (Non-Binding)")
    para(doc,
         "For each finding, answer a few quick questions, then drop it into one of three buckets. "
         "Again: these are notes for the engagement owner, not accept/reject decisions.")

    h2(doc, "Questions to ask")
    bullet(doc, "Is the affected target actually in scope for this engagement?")
    bullet(doc, "Does the cited evidence really support the claim (version string, response body, header)?")
    bullet(doc, "Is the impact real and reachable, or is this default/informational?")
    bullet(doc, "Is this a known false-positive class for the tool, or environment-specific (e.g. staging)?")
    bullet(doc, "Could it chain with anything else in the same scan to raise impact?")

    h2(doc, "Assessment buckets")
    make_table(
        doc,
        ["Bucket", "Use when", "Note to leave"],
        [
            ["Likely valid", "Evidence is concrete and the issue is plausibly real.",
             "Why it looks real + suspected severity."],
            ["Needs verification", "Plausible but needs hands-on confirmation of impact.",
             "What to test to confirm/deny."],
            ["Likely noise / informational",
             "Default config, out-of-scope, or known FP pattern.",
             "Why it can probably be deprioritized."],
        ],
        widths=[1.7, 3.0, 2.5],
        font_size=9,
    )

    h2(doc, "Applying it to the Next.js example")
    para(doc,
         "The version string is directly observable in the served bundle, so the detection itself "
         "is Likely valid \u2014 the dependency really is outdated. However, it is a dependency-only "
         "finding on a non-production staging portal and is rated Low, so the practical impact "
         "hinges on whether any of the cited CVEs are actually reachable in this app. A good "
         "non-binding note would be:")
    callout(doc,
            "\u201CLikely valid detection (Next.js 15.5.12 confirmed in main-*.js on staging portal). "
            "Low impact as written \u2014 dependency-only, non-prod. Worth a quick check of whether any "
            "cited CVE is reachable via the app's actual usage before the owner prioritizes the upgrade.\u201D",
            color=NAVY)

    # ---------------------------------------------------------------- 8
    page_break(doc)
    h1(doc, "8. The Dashboard We Want Eventually")
    para(doc,
         "Triage is only as good as the visibility into which scans ran and which succeeded. The "
         "target is a single \u201CDiscovery Agents Health\u201D view that a reviewer opens each morning to "
         "drive the workflow in Section 3. The pieces below describe what that view should show.")

    h2(doc, "Top-line health tiles")
    kpi_row(doc, [
        ("Scans Count", "3"),
        ("Scans Failed", "0"),
        ("Error Rate", "33.33%"),
        ("Avg Runtime", "01:09"),
        ("Slowest", "69m"),
    ])
    para(doc, "At-a-glance counts so a reviewer instantly knows the size and health of the morning's batch.",
         italic=True, color=GREY, size=9)

    h2(doc, "Filters")
    para(doc, "The view should be sliceable by the dimensions a reviewer actually triages along:")
    bullet(doc, "Org slug (which client).", bold_lead="Org: ")
    bullet(doc, "Date (default to today).", bold_lead="Date: ")
    bullet(doc, "Pentest tag (which engagement, e.g. #PT39025).", bold_lead="Pentest: ")
    bullet(doc, "Tool (ZAP / Nuclei / ffuf).", bold_lead="Tool: ")

    h2(doc, "Scans detail table")
    para(doc, "A row per scan with the fields needed to decide what to open first:")
    make_table(
        doc,
        ["org_slug", "pentest_tag", "level", "scan_status", "runtime_min", "created_at"],
        [
            ["cortechsai", "#PT38928", "low", "failed", "null", "Jun 24, 12:04 PM"],
            ["finzly", "#PT39135", "high", "in_progress", "null", "Jun 24, 12:04 PM"],
            ["givinga", "#PT39025", "high", "completed", "69", "Jun 24, 11:58 AM"],
        ],
        widths=[1.2, 1.2, 0.7, 1.2, 1.0, 1.6],
        font_size=8.5,
    )
    para(doc,
         "Plus scan_started_at and scan_completed_at columns (omitted above for width). The "
         "completed, high-level givinga scan is exactly the kind of row a reviewer should click "
         "into first.", italic=True, color=GREY, size=9)

    h2(doc, "Findings list (drill-down)")
    para(doc, "Clicking a scan should reach a findings/scan list with at least:")
    make_table(
        doc,
        ["Column", "Purpose"],
        [
            ["Tool", "Which scanner produced the row (zap, nuclei, ffuf)."],
            ["Type", "vulnerability / reconnaissance / data_processor."],
            ["Scan start / Scan end", "When it ran \u2014 freshness and runtime."],
            ["Status", "Completed / Failed \u2014 the filter that drives triage."],
            ["Actions / Download", "Open findings or pull the raw report artifact (e.g. SARIF, logs)."],
        ],
        widths=[2.0, 5.2],
        font_size=9,
    )

    h2(doc, "Requirements summary")
    numbered(doc, "One morning view that lists every scheduled scan and its status, filterable by org, date, pentest, and tool.")
    numbered(doc, "A clear Completed-vs-Failed signal so reviewers can jump straight to reviewable output.")
    numbered(doc, "One-click access from a scan to its findings and its raw artifact (report + tool log).")
    numbered(doc, "Health metrics (count, failed, error rate, runtime) to track scanner reliability over time.")
    numbered(doc, "A lightweight place to leave non-binding triage notes per finding for the engagement owner.")

    # ---------------------------------------------------------------- Appendix
    page_break(doc)
    h1(doc, "Appendix A \u2014 Glossary")
    make_table(
        doc,
        ["Term", "Meaning"],
        [
            ["ZAP", "OWASP Zed Attack Proxy \u2014 dynamic web app scanner (DAST)."],
            ["Nuclei", "Template-based vulnerability scanner matching signatures to targets."],
            ["ffuf", "\u201CFuzz Faster U Fool\u201D \u2014 content/path discovery fuzzer (reconnaissance)."],
            ["retire.js", "Library that flags JavaScript dependencies with known vulnerabilities; "
                          "runs as a ZAP passive rule."],
            ["Passive vs active scan", "Passive observes existing traffic/responses; active sends "
                                       "crafted probes. Passive findings carry less risk of FPs."],
            ["SARIF", "Static Analysis Results Interchange Format \u2014 the JSON report format ZAP emits."],
            ["CWE-1395", "Dependency on a vulnerable third-party component."],
            ["Pentest tag", "Engagement identifier, e.g. #PT39025."],
        ],
        widths=[1.8, 5.4],
        font_size=9,
    )

    h1(doc, "Appendix B \u2014 References")
    bullet(doc, "Discovery Agents Health dashboard (Looker Studio) \u2014 morning scan status view.")
    bullet(doc, "Engagement findings view \u2014 per-pentest scanner output and triage.")
    bullet(doc, "Vercel / Next.js security advisories \u2014 detail for the CVEs cited in Section 6.")
    bullet(doc, "Tool docs: OWASP ZAP, Nuclei (ProjectDiscovery), ffuf \u2014 capabilities and report formats.")

    para(doc,
         "Working draft \u2014 process proposal for scaling daily scanner-findings triage.",
         italic=True, color=GREY, size=9)

    out = os.path.join(HERE, "Discovery_Scanner_Findings_Triage.docx")
    doc.save(out)
    return out


if __name__ == "__main__":
    f = build_doc()
    print("Wrote:", f)
