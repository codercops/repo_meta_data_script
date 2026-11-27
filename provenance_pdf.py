"""Client-readable PDF companion for a repository provenance JSON report.

The JSON remains the technical record. This renderer includes every recorded
finding, check, scored signal and limitation while keeping raw logs and local
filesystem paths out of the client-facing document.
"""

from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import re
from typing import Any, Dict, List


NAVY = "#10283F"
TEAL = "#087F8C"
INK = "#20334A"
MUTED = "#5D6D7C"
PALE = "#F2F7F8"
PALE_BLUE = "#F2F5F9"
LINE = "#DCE5E9"
RED = "#A83F49"
AMBER = "#8B661E"


FINDING_NAMES = {
    "currently_public": "Repository currently public",
    "historical_public_repository": "Historical public record",
    "public_to_private_transition": "Public-to-private visibility change",
    "public_commit_match": "Commit found in public history",
    "archive_origin_snapshot_match": "Matching archived snapshot",
    "public_fork_ancestry": "Public parent repository",
    "fork_relationship": "Fork relationship",
    "reference_commit_match": "Commit match with supplied reference",
    "reference_source_match": "File match with supplied reference",
    "repository_links": "Repository links in local files",
    "additional_remote": "Additional Git remote",
    "deleted_license_history": "Deleted license in Git history",
    "history_coverage_gap": "Incomplete local Git history",
    "native_visibility_change_unresolved": "Visibility-change direction unresolved",
    "repository_identity_conflict": "Conflicting repository identity",
}

SIGNAL_NAMES = {
    "current_public_visibility": "Current public visibility",
    "historical_public_trace": "Historical public record",
    "public_commit_match": "Exact public commit match",
    "archived_origin_snapshot_match": "Archived origin snapshot match",
    "public_fork_ancestry": "Public parent repository",
    "supplied_reference_match": "Supplied reference code match",
    "fork_relationship": "Fork relationship",
    "stars": "Stars",
    "subscribers": "Subscribers",
    "forks": "Forks",
    "upstream_links_or_remotes": "Links or additional remotes",
    "deleted_license": "Deleted license history",
    "open_source_license_artifact": "Open-source license file",
    "deleted_readme": "Deleted README history",
    "large_tree_short_history": "Large codebase, short history",
    "contributor_metadata": "Contributor metadata (context only)",
    "clone_history": "Clone history (not collected)",
}


def _text(value: Any, limit: int = 250) -> str:
    if value is None:
        return "Unknown"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()
    return cleaned[:limit] + ("..." if len(cleaned) > limit else "")


def _html(value: Any, limit: int = 250) -> str:
    return escape(_text(value, limit), quote=False)


def _label(value: Any) -> str:
    return _text(value, 90).replace("_", " ").title().replace(" Api", " API")


def _basename(value: Any) -> str:
    return _text(str(value or "Unknown").replace("\\", "/").rsplit("/", 1)[-1], 120)


def _date(value: Any) -> str:
    if isinstance(value, (int, float)):
        try:
            seconds = value / 1000 if value > 10**11 else value
            return datetime.fromtimestamp(seconds, timezone.utc).strftime("%d %b %Y, %H:%M UTC")
        except (OverflowError, OSError, ValueError):
            return _text(value, 50)
    if not value:
        return "Unknown"
    raw = str(value)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc)
            return parsed.strftime("%d %b %Y, %H:%M UTC")
        return parsed.strftime("%d %b %Y, %H:%M")
    except ValueError:
        return _text(raw, 50)


def _visibility(metadata: Dict[str, Any]) -> str:
    value = metadata.get("visibility")
    if isinstance(value, str) and value in {"public", "private", "internal"}:
        return value.title()
    private = metadata.get("is_private")
    return "Private" if private is True else "Public" if private is False else "Unknown"


def _repo_name(result: Dict[str, Any]) -> str:
    repo = result.get("repository") or {}
    metadata = result.get("provider_metadata") or {}
    name = (repo.get("repository_name") or metadata.get("full_name") or
            repo.get("github_name"))
    if name:
        return _text(name, 120)
    target = repo.get("target") or "Repository not identified"
    return _basename(target)


def _audit_summary(audit: Dict[str, Any]) -> str:
    reason = audit.get("reason")
    labels = {
        "matching_audit_finding": "Matching audit evidence found",
        "audit_read_succeeded_within_retention": "Audit read; no matching event in the checked window",
        "audit_incomplete": "Audit read was incomplete",
        "audit_unavailable": "Audit access unavailable",
        "audit_not_requested": "Audit check not requested",
        "personal_account_provenance_only": "Personal account: audit log not collected",
        "offline": "Online audit check skipped",
    }
    return labels.get(reason, "Audit status unavailable")


def _decision(result: Dict[str, Any]) -> Dict[str, str]:
    if result.get("public_to_private_transition") is True:
        return {"title": "Prior public exposure confirmed",
                "summary": "A matching record explicitly shows this repository changing from public to private.",
                "color": RED}
    if result.get("ever_public") is True:
        return {"title": "Public exposure confirmed",
                "summary": "A matching public observation exists. A public-to-private change was not established.",
                "color": RED}
    if result.get("status") == "PUBLIC_CODE_MATCH":
        return {"title": "Public code connection found",
                "summary": "Code or history matches a public source, but this repository's past visibility is unconfirmed.",
                "color": AMBER}
    return {"title": "Historical visibility unconfirmed",
            "summary": "The available checks did not confirm past public exposure. This does not prove the repository was always private.",
            "color": TEAL}


def _source(value: Any) -> str:
    raw = str(value or "")
    if raw.startswith("import:"):
        return "Imported evidence file"
    if raw.startswith("local_reference:"):
        return "Supplied reference repository"
    if raw == "local_git":
        return "Local Git history"
    if raw == "local_files":
        return "Local repository files"
    if raw == "provider_metadata":
        return "Provider repository metadata"
    return _label(raw or "Source unavailable")


def _finding_detail(item: Dict[str, Any]) -> str:
    kind = item.get("kind")
    messages = {
        "currently_public": "The provider reported that the repository was public at the time of this check.",
        "historical_public_repository": "A historical public record was associated with this repository.",
        "public_to_private_transition": "A visibility record explicitly changed from public to private.",
        "public_commit_match": "A sampled commit was also found in public history. Shared history alone does not prove that this exact repository was public.",
        "archive_origin_snapshot_match": "A dated archive visit matched this repository's Git history. It does not itself record a privacy-setting change.",
        "public_fork_ancestry": "The provider reported a public parent repository. This is a public-origin code connection, not proof of a visibility transition.",
        "fork_relationship": "The provider identified a fork relationship. A fork can also be private.",
        "reference_commit_match": "Local Git history shares exact commits with a supplied reference repository. The reference's public origin needs independent verification.",
        "reference_source_match": "Source files match a supplied reference repository. The reference's public origin needs independent verification.",
        "deleted_license_history": "A license file was deleted in local history. This is a weak clue and can be normal maintenance.",
        "repository_links": "Repository files contain links to other repositories. Links alone do not verify public exposure.",
        "additional_remote": "The local clone has another Git remote. A remote URL alone does not establish past visibility.",
        "history_coverage_gap": "The available local Git history may be incomplete.",
        "native_visibility_change_unresolved": "A privacy-setting event was found, but the old and new values do not establish its direction.",
        "repository_identity_conflict": "Provider observations disagreed about the repository identity; this cannot confirm exposure.",
    }
    parts = [messages.get(kind, "The investigation recorded this observation.")]
    old, new = item.get("previous_visibility"), item.get("visibility")
    if old is not None or new is not None:
        parts.append("Recorded change: %s to %s." % (_text(old, 30), _text(new, 30)))
    if item.get("timestamp"):
        parts.append("Date: %s." % _date(item["timestamp"]))
    if item.get("event_id"):
        parts.append("Event ID: %s." % _text(item["event_id"], 80))
    if item.get("repository_id") is not None:
        parts.append("Repository ID: %s." % _text(item["repository_id"], 80))
    if item.get("repository_name"):
        parts.append("Matched repository: %s." % _text(item["repository_name"], 110))
    for key, label in (("matched_commit_count", "Matching commits"),
                       ("matched_source_file_count", "Matching files"),
                       ("matched_source_percent", "Matching source share")):
        if item.get(key) is not None:
            parts.append("%s: %s%s." % (label, _text(item[key], 25), "%" if key.endswith("percent") else ""))
    shas = item.get("shas")
    if isinstance(shas, list) and shas:
        parts.append("Example commit: %s." % _text(shas[0], 12))
    return " ".join(parts)


def _check_status(check: Dict[str, Any]) -> str:
    status = check.get("status")
    labels = {
        200: "Read successfully", 401: "Authentication required",
        403: "Access denied", 404: "Not found or inaccessible",
        429: "Rate limited", "bounded_window": "Read within available window",
        "not_requested": "Not requested", "offline": "Offline - not run",
        "personal_account_provenance_only": "Personal account - not collected",
        "token_required": "Token required",
        "atlassian_org_id_and_admin_token_required": "Organization admin access required",
        "verified_repository_identity_required": "Repository identity unverified",
    }
    return labels.get(status, _label(status)) if isinstance(status, (str, int)) else "Unknown"


def _check_detail(check: Dict[str, Any]) -> str:
    details = []
    for key, label in (("pages", "Pages"), ("records_read", "Records"),
                       ("recognized_visibility_events", "Visibility events"),
                       ("records", "Records")):
        if check.get(key) is not None:
            details.append("%s: %s" % (label, _text(check[key], 20)))
    if check.get("has_more") is True:
        details.append("More pages existed")
    if check.get("sha"):
        details.append("Sample commit: %s" % _text(check["sha"], 12))
    return "; ".join(details) or "-"


def _signal_status(signal: Dict[str, Any]) -> str:
    return {"detected": "Found", "not_detected": "Not seen", "unavailable": "Unavailable"}.get(
        signal.get("status"), "Unknown")


def _font_names() -> tuple:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import reportlab

    candidates = [
        (Path(r"C:\Windows\Fonts\segoeui.ttf"), Path(r"C:\Windows\Fonts\segoeuib.ttf")),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
         Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
        (Path("/Library/Fonts/Arial.ttf"), Path("/Library/Fonts/Arial Bold.ttf")),
        (Path(reportlab.__file__).parent / "fonts" / "Vera.ttf",
         Path(reportlab.__file__).parent / "fonts" / "VeraBd.ttf"),
    ]
    for regular, bold in candidates:
        if regular.is_file() and bold.is_file():
            if "ClientReport" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("ClientReport", str(regular)))
                pdfmetrics.registerFont(TTFont("ClientReport-Bold", str(bold)))
                pdfmetrics.registerFontFamily("ClientReport", normal="ClientReport",
                                              bold="ClientReport-Bold")
            return "ClientReport", "ClientReport-Bold"
    return "Helvetica", "Helvetica-Bold"


def build_client_pdf(result: Dict[str, Any], output_path: Any) -> None:
    """Render a client-readable PDF from one provenance result dictionary."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import (HRFlowable, KeepTogether, LongTable, PageBreak,
                                   Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    regular, bold = _font_names()
    styles = {
        "title": ParagraphStyle("title", fontName=bold, fontSize=22, leading=27,
                                textColor=colors.HexColor(NAVY), spaceAfter=6),
        "subtitle": ParagraphStyle("subtitle", fontName=regular, fontSize=9.2, leading=13,
                                   textColor=colors.HexColor(MUTED), spaceAfter=13),
        "section": ParagraphStyle("section", fontName=bold, fontSize=12.5, leading=17,
                                  textColor=colors.HexColor(NAVY), spaceBefore=14, spaceAfter=8),
        "body": ParagraphStyle("body", fontName=regular, fontSize=9.2, leading=14,
                               textColor=colors.HexColor(INK), spaceAfter=8, splitLongWords=1),
        "small": ParagraphStyle("small", fontName=regular, fontSize=8, leading=11.5,
                                textColor=colors.HexColor(MUTED), spaceAfter=3, splitLongWords=1),
        "bold": ParagraphStyle("bold", fontName=bold, fontSize=9.3, leading=13,
                               textColor=colors.HexColor(NAVY), spaceAfter=3, splitLongWords=1),
        "white_title": ParagraphStyle("white_title", fontName=bold, fontSize=16.5,
                                      leading=21, textColor=colors.white, spaceAfter=8),
        "white": ParagraphStyle("white", fontName=regular, fontSize=9,
                                leading=13.5, textColor=colors.white, spaceAfter=4),
        "table_head": ParagraphStyle("table_head", fontName=bold, fontSize=8,
                                     leading=11, textColor=colors.white),
        "table": ParagraphStyle("table", fontName=regular, fontSize=8.1,
                                leading=11.3, textColor=colors.HexColor(INK), splitLongWords=1),
    }

    def para(text: str, style: str = "body"):
        return Paragraph(text, styles[style])

    page_width, _ = A4
    content_width = page_width - 88
    doc = SimpleDocTemplate(str(output_path), pagesize=A4, leftMargin=44,
                            rightMargin=44, topMargin=90, bottomMargin=64,
                            title="Repository Public Visibility Review",
                            author="Repository Analysis Tool")

    def frame(canvas, document):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor(TEAL))
        canvas.roundRect(44, 790, 24, 24, 5, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont(bold, 12)
        canvas.drawCentredString(56, 797, "R")
        canvas.setFillColor(colors.HexColor(NAVY))
        canvas.setFont(bold, 8.5)
        canvas.drawString(77, 798, "REPOSITORY REVIEW")
        canvas.setFillColor(colors.HexColor(PALE_BLUE))
        canvas.roundRect(page_width - 135, 791, 91, 22, 11, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor(TEAL))
        canvas.setFont(bold, 7.5)
        canvas.drawCentredString(page_width - 89.5, 798,
                                "SAMPLE DATA" if result.get("_sample_data") is True else "CLIENT REPORT")
        canvas.setStrokeColor(colors.HexColor(LINE))
        canvas.line(44, 779, page_width - 44, 779)
        canvas.line(44, 52, page_width - 44, 52)
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.setFont(regular, 7.3)
        canvas.drawString(44, 39, "Fictional preview - no real repository was analyzed." if result.get("_sample_data") is True
                          else "Client summary. Detailed technical record: provenance.json")
        canvas.setFont(bold, 8)
        canvas.drawRightString(page_width - 44, 39, "Page %d" % document.page)
        canvas.restoreState()

    repository = result.get("repository") or {}
    metadata = result.get("provider_metadata") or {}
    estimate = result.get("public_exposure_estimate") or {}
    audit = estimate.get("audit") or {}
    evidence = [x for x in (result.get("evidence") or []) if isinstance(x, dict)]
    checks = [x for x in (result.get("checks") or []) if isinstance(x, dict)]
    signals = [x for x in (estimate.get("signals") or []) if isinstance(x, dict)]
    limitations = [x for x in (result.get("limitations") or []) if isinstance(x, str)]
    decision = _decision(result)
    provider = _label(repository.get("provider") or "Unknown provider")
    current = _visibility(metadata)
    score = estimate.get("likelihood_percent")
    score_text = "%s%%" % score if isinstance(score, (int, float)) else "N/A"
    transition = "Confirmed" if result.get("public_to_private_transition") is True else "Unknown"
    ever_public = "Confirmed" if result.get("ever_public") is True else "Unknown"
    automated = _label(result.get("recommendation") or "Manual review")

    story: List[Any] = []
    story.append(para("Was this repository ever public?", "title"))
    story.append(para("%s | %s | Generated %s" % (
        _html(_repo_name(result)), _html(provider), _html(_date(result.get("generated_at")))), "subtitle"))

    decision_cells = [
        para("ASSESSMENT RESULT", "white"),
        para(_html(decision["title"]), "white_title"),
        para(_html(decision["summary"]), "white"),
        para("Automated acceptance decision: %s" % _html(automated), "white"),
    ]
    decision_table = Table([[decision_cells]], colWidths=[content_width])
    decision_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(NAVY)),
        ("LEFTPADDING", (0, 0), (-1, -1), 17),
        ("RIGHTPADDING", (0, 0), (-1, -1), 17),
        ("TOPPADDING", (0, 0), (-1, -1), 15),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))
    story.extend([decision_table, Spacer(1, 15)])

    def card(label: str, value: str, detail: str):
        return [para(_html(label).upper(), "small"),
                para("<b>%s</b>" % _html(value), "bold"),
                para(_html(detail), "small")]

    metrics = Table([[
        card("Current access", current, "At report time"),
        card("Past exposure", ever_public, "Positive evidence only"),
        card("Heuristic", score_text, "Not a measured probability"),
    ]], colWidths=[content_width / 3] * 3)
    metrics.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PALE_BLUE)),
        ("LINEBEFORE", (1, 0), (2, 0), 6, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))
    story.append(metrics)

    story.append(para("What this means", "section"))
    if result.get("public_to_private_transition") is True:
        meaning = "A matching event records an earlier public period and a change to private. The current visibility is %s. The separate heuristic estimate does not use audit-event points." % current.lower()
    elif result.get("ever_public") is True:
        meaning = "Positive evidence shows public exposure, but the available record does not establish a public-to-private transition. The current visibility is %s." % current.lower()
    elif result.get("status") == "PUBLIC_CODE_MATCH":
        meaning = "The repository shares code or history with a public source. That connection does not, by itself, establish that this exact repository was public."
    else:
        meaning = "The checks did not confirm that this repository was previously public. Missing records or inaccessible sources cannot establish that it was always private."
    story.append(para(_html(meaning)))
    story.append(para("Audit review: <b>%s</b>. Public-to-private transition: <b>%s</b>." %
                      (_html(_audit_summary(audit)), _html(transition))))

    story.append(para("Key findings", "section"))
    priority = {"confirmed": 0, "code_match": 1, "lead": 2}
    highlights = sorted(evidence, key=lambda e: priority.get(e.get("strength"), 3))[:3]
    if highlights:
        for item in highlights:
            title = FINDING_NAMES.get(item.get("kind"), _label(item.get("kind")))
            story.append(para("<b>%s.</b> %s" % (_html(title), _html(_finding_detail(item), 420))))
    else:
        story.append(para("No positive public-origin finding was recorded in the available checks. This is not a clean-history certificate."))

    story.append(para("Recommended next step", "section"))
    if result.get("recommendation") == "REJECT":
        action = "Do not accept automatically under the current private-only policy. Verify the cited provider record and ask the repository owner to explain the public period and code rights."
    else:
        action = "Arrange a manual review of the available evidence and coverage gaps before deciding whether the repository meets your policy."
    action_table = Table([[para(_html(action))]], colWidths=[content_width])
    action_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PALE)),
        ("LEFTPADDING", (0, 0), (-1, -1), 13),
        ("RIGHTPADDING", (0, 0), (-1, -1), 13),
        ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(action_table)

    story.append(PageBreak())
    story.append(para("Evidence behind the result", "title"))
    story.append(para("Every recorded finding is listed below. 'Confirmed' refers to the tool's identity-matching rules; imported records still need independent source verification.", "subtitle"))
    if not evidence:
        story.append(para("No positive findings were recorded. This does not prove the repository was always private."))
    for index, item in enumerate(evidence, 1):
        title = FINDING_NAMES.get(item.get("kind"), _label(item.get("kind")))
        strength = {"confirmed": "CONFIRMED", "code_match": "PUBLIC CODE LINK",
                    "lead": "INVESTIGATIVE CLUE"}.get(item.get("strength"), "OBSERVATION")
        source = _source(item.get("source"))
        if item.get("independently_fetched") is False:
            source += " - not independently fetched"
        card_content = [
            para("%d. %s <font color='%s'>[%s]</font>" % (
                index, _html(title), TEAL if strength == "CONFIRMED" else AMBER,
                _html(strength)), "bold"),
            para(_html(_finding_detail(item), 650)),
            para("Source: %s" % _html(source), "small"),
        ]
        card_table = Table([[card_content]], colWidths=[content_width])
        card_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PALE_BLUE)),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(KeepTogether([card_table, Spacer(1, 8)]))

    story.append(PageBreak())
    story.append(para("Checks and coverage", "title"))
    story.append(para("A completed check covers only the source and time window shown. An unavailable or negative check never proves a private lifetime.", "subtitle"))
    if checks:
        check_rows = [[para("CHECK", "table_head"), para("RESULT", "table_head"),
                       para("DETAIL", "table_head")]]
        for item in checks:
            check_rows.append([
                para(_html(_label(item.get("check"))), "table"),
                para(_html(_check_status(item)), "table"),
                para(_html(_check_detail(item)), "table"),
            ])
        check_table = LongTable(check_rows, colWidths=[189, 145, content_width - 334],
                                repeatRows=1, hAlign="LEFT")
        check_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(NAVY)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor(PALE_BLUE), colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(check_table)
    else:
        story.append(para("No check records were available."))

    story.append(para("How the heuristic score was calculated", "section"))
    story.append(para("<b>%s</b> is an assumption-based evidence index, not a statistical probability. Audit events are excluded from the score. Positive signals add points within group caps; missing signals add no points." % _html(score_text)))
    if signals:
        signal_rows = [[para("SIGNAL", "table_head"), para("STATUS", "table_head"),
                        para("WEIGHT", "table_head"), para("ADDED", "table_head")]]
        for item in signals:
            name = SIGNAL_NAMES.get(item.get("signal"), _label(item.get("signal")))
            name_cell = [para(_html(name), "table")]
            if item.get("contribution_points", 0) > 0 and item.get("explanation"):
                name_cell.append(para(_html(item["explanation"], 220), "small"))
            signal_rows.append([
                name_cell,
                para(_html(_signal_status(item)), "table"),
                para(_html(item.get("weight", 0)), "table"),
                para("+%s" % _html(item.get("contribution_points", 0)), "table"),
            ])
        signal_table = LongTable(signal_rows, colWidths=[content_width - 224, 95, 65, 64],
                                 repeatRows=1, hAlign="LEFT")
        signal_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(NAVY)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor(PALE_BLUE), colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(signal_table)
        group_points = estimate.get("group_points") or {}
        if isinstance(group_points, dict) and group_points:
            groups = ", ".join("%s %s" % (_label(k), _text(v, 10)) for k, v in group_points.items())
            story.append(Spacer(1, 6))
            story.append(para("Group points: %s. Final displayed score: <b>%s</b>." %
                              (_html(groups, 400), _html(score_text)), "small"))
    else:
        story.append(para("No scored signal breakdown was available."))

    story.append(para("Coverage limits", "section"))
    for item in limitations + [x for x in (estimate.get("limitations") or []) if isinstance(x, str)]:
        story.append(para("- %s" % _html(item, 500), "small"))
    if not limitations and not estimate.get("limitations"):
        story.append(para("No additional limitations were recorded. Missing evidence still cannot verify an always-private history.", "small"))

    sources = result.get("evidence_sources") or []
    references = result.get("public_references") or []
    if sources or references:
        story.append(para("Supplied evidence and references", "section"))
        for item in sources:
            if isinstance(item, dict):
                name = _basename(item.get("path") or "Unknown file")
                story.append(para("Evidence file <b>%s</b>: %s; records read %s; matched records %s." % (
                    _html(name), _html(_label(item.get("status"))),
                    _html(item.get("records_read")), _html(item.get("matched_repository_records"))), "small"))
        for item in references:
            if isinstance(item, dict):
                name = _basename(item.get("path") or "Unknown reference")
                story.append(para("Reference <b>%s</b>: %s; shared commits %s; matching files %s." % (
                    _html(name), _html(_label(item.get("status"))),
                    _html(item.get("shared_commits")), _html(item.get("matched_source_files"))), "small"))

    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=0.7, color=colors.HexColor(LINE)))
    story.append(Spacer(1, 6))
    story.append(para("This client report summarizes the captured observations. The companion provenance.json retains the complete structured record, including technical values and evidence-source hashes.", "small"))
    doc.build(story, onFirstPage=frame, onLaterPages=frame)
