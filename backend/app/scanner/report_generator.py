from __future__ import annotations

import datetime as dt
from io import BytesIO
from html import escape
from collections import Counter

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from . import risk_engine, file_selector
from ..privacy import redact_text


MAX_REVIEW_LEADS = 10


def _safe(value) -> str:
    """Redact sensitive values before escaping them for ReportLab HTML markup."""
    text = redact_text(str(value or "")) or ""
    return escape(text)


def _confidence_label(value):
    if value is None:
        return "POSSIBLE"
    if value >= 0.90:
        return "CONFIRMED"
    if value >= 0.70:
        return "LIKELY"
    return "POSSIBLE"


def _risk_color(label: str):
    return {
        "CRITICAL": colors.HexColor("#b91c1c"),
        "HIGH": colors.HexColor("#c2410c"),
        "MEDIUM": colors.HexColor("#a16207"),
        "LOW": colors.HexColor("#15803d"),
    }.get(label, colors.HexColor("#374151"))


def _risk_label_for_score(label: str) -> str:
    # The engine historically returns labels such as "LOW RISK". Keep the
    # customer report grammatically clean and avoid "LOW RISK RISK".
    return str(label or "UNKNOWN").replace(" RISK RISK", " RISK").strip()


def _friendly_capability(finding) -> str:
    mapping = {
        "delete": "Possible database deletion",
        "drop": "Possible database table deletion",
        "truncate": "Possible database table clearing",
        "update": "Possible database change",
        "remove": "Possible data removal",
        "refund": "Possible refund",
        "charge": "Possible payment charge",
        "transfer": "Possible money transfer",
        "payout": "Possible payout",
        "send": "Possible outbound message",
        "execute": "Possible command execution",
        "shell execution": "Possible shell command execution",
        "deploy": "Possible deployment or infrastructure change",
        "terminate": "Possible infrastructure shutdown",
        "merge": "Possible code merge",
        "push": "Possible code push",
        "exposed_secret": "Exposed credential or API key",
        "hardcoded_credential": "Hardcoded credential",
        "data_exfiltration": "Sensitive data sent externally",
        "unguarded_endpoint": "Potentially unprotected sensitive endpoint",
        "command_injection": "Potential command injection",
        "sql_injection": "Potential SQL injection",
        "export": "Possible data export",
    }
    return mapping.get(str(getattr(finding, "capability", "") or "").lower(), "Potential high-impact action")


def _review_bucket(path: str) -> str:
    p = (path or "").replace("\\", "/").lower()
    if file_selector.is_non_runtime_path(path):
        if any(token in p for token in ("/test", "tests/", "__tests__/", ".test.", ".spec.")):
            return "Tests"
        if any(token in p for token in ("docs/", "documentation/", "readme", "example", "examples/")):
            return "Documentation / examples"
        return "Configuration / tooling / specifications"
    return "Application runtime code"


def _review_priority(finding):
    # Prefer runtime code, then stronger confidence, then more consequential
    # capability. This affects presentation only; scoring is unchanged.
    runtime_bonus = 1 if _review_bucket(finding.file_path) == "Application runtime code" else 0
    confidence = float(finding.confidence or 0)
    severity_weight = {
        "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
    }.get(finding.severity, 0)
    return (runtime_bonus, confidence, severity_weight)


def _select_review_leads(findings):
    """Return a small, useful set of unscored leads for the customer PDF.

    The dashboard remains the exhaustive view. The PDF deliberately avoids
    dumping hundreds of regex matches from tests/docs/specs onto the customer.
    Duplicate-looking leads are collapsed by path + capability + line bucket.
    """
    leads = [f for f in findings if not f.scored]
    leads.sort(key=_review_priority, reverse=True)
    selected = []
    seen = set()
    for f in leads:
        key = (
            f.file_path,
            str(f.capability or f.title).lower(),
            int((f.line_number or 0) // 20),
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(f)
        if len(selected) >= MAX_REVIEW_LEADS:
            break
    return selected


def build_scan_report_pdf(repository, scan, findings, score_result, regression=None) -> bytes:
    """Build a customer-facing PDF from one completed scan.

    The report is intentionally human-readable. Confirmed/likely scored risks
    get the main attention. Unscored matches are summarized and only the most
    useful review leads are shown; the dashboard remains the exhaustive view.
    """
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Cover", parent=styles["Title"], alignment=TA_CENTER, fontSize=24, leading=29, spaceAfter=10))
    styles.add(ParagraphStyle(name="Sub", parent=styles["Normal"], alignment=TA_CENTER, fontSize=10, textColor=colors.HexColor("#6b7280"), leading=15))
    styles.add(ParagraphStyle(name="H1r", parent=styles["Heading1"], fontSize=16, leading=20, spaceBefore=8, spaceAfter=7))
    styles.add(ParagraphStyle(name="H2r", parent=styles["Heading2"], fontSize=12, leading=15, spaceBefore=7, spaceAfter=5))
    styles.add(ParagraphStyle(name="Bodyr", parent=styles["BodyText"], fontSize=9, leading=13, spaceAfter=5))
    styles.add(ParagraphStyle(name="Smallr", parent=styles["BodyText"], fontSize=7.5, leading=10, textColor=colors.HexColor("#6b7280")))
    styles.add(ParagraphStyle(name="RiskTitle", parent=styles["Heading3"], fontSize=10.5, leading=14, spaceAfter=3))

    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm)
    story = []
    score = score_result.get("score", scan.score)
    label = _risk_label_for_score(score_result.get("label", "UNKNOWN"))
    counts = score_result.get("counts", {})
    completed_at = scan.finished_at or dt.datetime.now(dt.UTC)

    open_scored = [f for f in findings if f.scored and f.status != "resolved"]
    unscored = [f for f in findings if not f.scored]
    bucket_counts = Counter(_review_bucket(f.file_path) for f in unscored)
    review_leads = _select_review_leads(findings)

    story += [
        Spacer(1, 12*mm),
        Paragraph("AI Safety Checkup", styles["Cover"]),
        Paragraph("Your AI Safety Report", styles["Cover"]),
        Spacer(1, 7*mm),
        Paragraph(f"<b>{_safe(repository.repo_name)}</b>", styles["Sub"]),
        Paragraph(_safe(repository.repo_url), styles["Sub"]),
        Paragraph(f"Scan completed: {_safe(completed_at.isoformat())}", styles["Sub"]),
        Spacer(1, 10*mm),
    ]

    summary = [
        [Paragraph("Safety Score", styles["Bodyr"]), Paragraph("Risk Level", styles["Bodyr"]), Paragraph("Confirmed / scored risks", styles["Bodyr"])],
        [Paragraph(f"<font size='22'><b>{score}/100</b></font>", styles["Bodyr"]), Paragraph(f"<font color='{_risk_color(label.replace(' RISK','')).hexval()}'><b>{_safe(label)}</b></font>", styles["Bodyr"]), Paragraph(str(len(open_scored)), styles["Bodyr"])],
    ]
    st = Table(summary, colWidths=[55*mm, 55*mm, 55*mm])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#f3f4f6")),
        ("BOX", (0,0), (-1,-1), 0.6, colors.HexColor("#d1d5db")),
        ("INNERGRID", (0,0), (-1,-1), 0.3, colors.HexColor("#e5e7eb")),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 8), ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story += [st, Spacer(1, 6*mm)]

    # Be explicit when a big repository was only partly analysed.
    cov = getattr(scan, "coverage", None)
    if cov:
        try:
            import json as _json
            c = _json.loads(cov) if isinstance(cov, str) else cov
            story.append(Paragraph(
                f"<b>Partial scan:</b> {_safe(c.get('files_scanned', 0))} of {_safe(c.get('files_total', 0))} source files were "
                "analysed (likely AI and runtime code first). The remaining files were skipped because of size or time limits, "
                "so this report may not cover the whole repository.", styles["Bodyr"]))
            story.append(Spacer(1, 4*mm))
        except (ValueError, TypeError, AttributeError):
            pass

    if open_scored:
        worst = max(open_scored, key=lambda f: risk_engine.SEVERITY_ORDER.index(f.severity))
        story.append(Paragraph(
            f"<b>What this means:</b> We found {len(open_scored)} confirmed or sufficiently supported risky AI-connected action(s). "
            f"The most serious finding is rated <b>{_safe(worst.severity)}</b>. Review the evidence and the approval controls before allowing the AI to trigger these actions.",
            styles["Bodyr"]
        ))
    else:
        story.append(Paragraph(
            "<b>Good news:</b> We did not find evidence that your AI can directly control a scored high-impact action using the checks performed in this scan.",
            styles["Bodyr"]
        ))

    if unscored:
        story.append(Paragraph(
            f"<b>Also worth knowing:</b> We found <b>{len(unscored)}</b> potential match(es) that need review. "
            "These do not lower your score because we could not prove that the AI controls the action. They are review leads, not confirmed risks.",
            styles["Bodyr"]
        ))

    story += [Paragraph("What your score means", styles["H1r"]), Paragraph(
        "Your score reflects risky AI-controlled actions that we could confirm with the current checks. "
        "A 100/100 score means we did not find enough confirmed evidence to deduct points; it does not mean the application is guaranteed to be secure. "
        "A lower score points you toward areas that deserve attention.", styles["Bodyr"])]

    story += [Paragraph("What your AI can do", styles["H1r"])]
    capabilities = {}
    for f in open_scored:
        key = (f.category, f.capability or f.title)
        capabilities[key] = f
    cap_rows = [["Action", "AI control", "Risk", "Where"]]
    for f in sorted(capabilities.values(), key=lambda x: -risk_engine.SEVERITY_ORDER.index(x.severity)):
        control = "Confirmed" if f.ai_controlled is True else "Not confirmed" if f.ai_controlled is False else "Unknown"
        cap_rows.append([_friendly_capability(f), control, f.severity, f"{_safe(f.file_path)}:{f.line_number}"])
    if len(cap_rows) == 1:
        cap_rows.append(["No confirmed risky actions", "Not found", "—", "—"])
    cap_table = Table(cap_rows, colWidths=[55*mm, 30*mm, 25*mm, 55*mm], repeatRows=1)
    cap_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#20242a")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 7.5),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#d1d5db")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
        ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story += [cap_table, Spacer(1, 5*mm)]

    if open_scored:
        story.append(Paragraph("Your biggest risks", styles["H1r"]))
        top = sorted(open_scored, key=lambda f: (-risk_engine.SEVERITY_ORDER.index(f.severity), -(f.confidence or 0)))[:10]
        for idx, f in enumerate(top, 1):
            story.append(Paragraph(f"{idx}. {_friendly_capability(f)} — <b>{_safe(f.severity)}</b>", styles["RiskTitle"]))
            story.append(Paragraph(
                f"<b>Why it matters:</b> {_safe(f.description or 'This action may be influenced by AI-generated information.')}", styles["Bodyr"]))
            story.append(Paragraph(
                f"<b>Where:</b> {_safe(f.file_path)}:{f.line_number} &nbsp; <b>Confidence:</b> {_confidence_label(f.confidence)} ({(f.confidence or 0)*100:.0f}%)",
                styles["Bodyr"]))
            if f.capability_chain:
                story.append(Paragraph(f"<b>How the data moves:</b> {_safe(' → '.join(str(x) for x in f.capability_chain))}", styles["Bodyr"]))
            if f.snippet:
                # Keep only a short, readable evidence line in the customer report.
                snippet = str(f.snippet).replace("\n", " ")
                if len(snippet) > 500:
                    snippet = snippet[:500] + "…"
                story.append(Paragraph(f"<b>Code evidence:</b> <font name='Courier'>{_safe(snippet)}</font>", styles["Bodyr"]))
            story.append(Paragraph(f"<b>What you can do:</b> {_safe(f.recommendation)}", styles["Bodyr"]))
            story.append(Spacer(1, 2*mm))

    security_findings = [f for f in open_scored if str(f.category or "") in {"SECRETS", "DATA_EXPOSURE", "AUTHENTICATION", "INJECTION"}]
    if security_findings:
        story.append(PageBreak())
        story.append(Paragraph("Application security issues", styles["H1r"]))
        story.append(Paragraph(
            "In addition to AI-controlled actions, we check for common application-security problems that can expose credentials, data, or sensitive endpoints. These findings are based on static evidence; they do not prove that someone has already attacked the application.",
            styles["Bodyr"]))
        for idx, f in enumerate(security_findings[:10], 1):
            story.append(Paragraph(f"{idx}. {_safe(f.title)} — <b>{_safe(f.severity)}</b>", styles["RiskTitle"]))
            story.append(Paragraph(f"<b>What we found:</b> {_safe(f.description)}", styles["Bodyr"]))
            story.append(Paragraph(f"<b>Where:</b> {_safe(f.file_path)}:{f.line_number} &nbsp; <b>Confidence:</b> {_confidence_label(f.confidence)} ({(f.confidence or 0)*100:.0f}%)", styles["Bodyr"]))
            if f.snippet:
                story.append(Paragraph(f"<b>Evidence:</b> <font name='Courier'>{_safe(str(f.snippet)[:500])}</font>", styles["Bodyr"]))
            story.append(Paragraph(f"<b>What you can do:</b> {_safe(f.recommendation)}", styles["Bodyr"]))
            story.append(Spacer(1, 2*mm))

    if unscored:
        story.append(PageBreak())
        story.append(Paragraph("Things worth checking", styles["H1r"]))
        story.append(Paragraph(
            f"We found {len(unscored)} potential matches. Most were not strong enough to count as risks. "
            f"To keep this report useful, we show the {min(MAX_REVIEW_LEADS, len(review_leads))} most useful review leads below. "
            "The dashboard contains the full list.", styles["Bodyr"]))

        if bucket_counts:
            rows = [["Where matches were found", "Number"]]
            order = ["Application runtime code", "Configuration / tooling / specifications", "Tests", "Documentation / examples"]
            for bucket in order:
                if bucket_counts.get(bucket):
                    rows.append([bucket, str(bucket_counts[bucket])])
            bt = Table(rows, colWidths=[125*mm, 35*mm], repeatRows=1)
            bt.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#20242a")),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 8),
                ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#d1d5db")),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
                ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ]))
            story += [bt, Spacer(1, 5*mm)]

        for idx, f in enumerate(review_leads, 1):
            story.append(Paragraph(f"{idx}. {_friendly_capability(f)}", styles["RiskTitle"]))
            story.append(Paragraph(
                f"<b>Where:</b> {_safe(f.file_path)}:{f.line_number} &nbsp; "
                f"<b>Status:</b> Potential — needs review &nbsp; <b>Confidence:</b> {_confidence_label(f.confidence)}",
                styles["Bodyr"]))
            story.append(Paragraph(
                "<b>What we found:</b> We found code or text that looks related to this action, but the scanner could not prove that AI-generated information can reach it.",
                styles["Bodyr"]))
            if f.capability_chain:
                story.append(Paragraph(f"<b>What we can see:</b> {_safe(' → '.join(str(x) for x in f.capability_chain))}", styles["Bodyr"]))
            story.append(Paragraph(f"<b>What you can do:</b> {_safe(f.recommendation)}", styles["Bodyr"]))
            story.append(Spacer(1, 2*mm))

        omitted = len(unscored) - len(review_leads)
        if omitted > 0:
            story.append(Paragraph(
                f"<b>{omitted} additional low-confidence matches are available in the dashboard.</b> "
                "They were not expanded here because they were duplicates or came from lower-priority files such as tests, specifications, tooling, documentation, or examples.",
                styles["Smallr"]))

    story.append(PageBreak())
    story.append(Paragraph("What changed since the last scan", styles["H1r"]))
    if regression and regression.get("has_baseline"):
        delta = regression.get("score_delta")
        direction = "improved" if (delta or 0) > 0 else "got worse" if (delta or 0) < 0 else "stayed the same"
        story.append(Paragraph(
            f"Your previous score was <b>{regression.get('previous_score')}</b> and your current score is <b>{regression.get('current_score')}</b>. "
            f"Your safety score has <b>{direction}</b> since the previous scan.", styles["Bodyr"]))
        if regression.get("new_findings"):
            story.append(Paragraph(f"New or escalated scored risks: <b>{len(regression.get('new_findings', []))}</b>.", styles["Bodyr"]))
        if regression.get("resolved_findings"):
            story.append(Paragraph(f"Resolved scored risks: <b>{len(regression.get('resolved_findings', []))}</b>.", styles["Bodyr"]))
    else:
        story.append(Paragraph(
            "This is the first completed scan for this repository, so there is no previous scan to compare with. "
            "Run another scan after code changes to see whether the safety picture improves or gets worse.", styles["Bodyr"]))

    story += [
        Paragraph("How we checked your code", styles["H1r"]),
        Paragraph(
            "We looked for AI models and agents, actions the application can perform, connections between AI output and those actions, "
            "and safety controls such as approval checks and limits. We only count a risk in the score when the current analyzer has enough evidence to support the connection.",
            styles["Bodyr"]),
        Paragraph("Important note", styles["H1r"]),
        Paragraph(
            "AI Safety Checkup uses static analysis and heuristic risk scoring. A finding is evidence for review, not proof that an application is vulnerable. "
            "Unscored items are intentionally kept separate when the evidence is weaker. Security teams should validate important findings in context.",
            styles["Bodyr"]),
        Paragraph(
            "This report was generated from the selected scan. Full repository source code is not included. Short source excerpts appear only when the repository scan was configured to retain encrypted evidence snippets.",
            styles["Smallr"]),
    ]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(15*mm, 8*mm, "AI Safety Checkup — Customer Safety Report")
        canvas.drawRightString(A4[0]-15*mm, 8*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
