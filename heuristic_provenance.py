"""Explainable, uncalibrated public-origin estimates for unavailable audit logs.

Weights are policy assumptions, not learned probabilities. Missing observations
never increase weights or count as evidence that a repository was private.
"""
from pathlib import Path
import re


GROUP_CAPS = {"public_trace": 95, "relationship": 8, "engagement": 6,
              "documentation": 6, "history": 4, "context": 0}
MODEL_VERSION = "public-origin-heuristic-v1"


def audit_availability(checks, evidence, *, requested, offline):
    """An empty successful audit is available; failed/truncated reads are not."""
    audit_findings = [e for e in evidence if e.get("strength") == "confirmed" and (
        str(e.get("source", "")).endswith("_audit_log") or
        e.get("event_type") in {"repo.access", "repo.create"} or
        e.get("kind") == "public_to_private_transition")]
    if audit_findings:
        return {"available": True, "reason": "matching_audit_finding"}
    if any(c.get("check") == "github_audit_log" and
           c.get("status") == "personal_account_provenance_only" for c in checks):
        return {"available": False, "reason": "personal_account_provenance_only",
                "checks": [c for c in checks if c.get("check") == "github_audit_log"]}
    audits = [c for c in checks if str(c.get("check", "")).endswith("_audit_log")]
    complete = bool(audits and audits[-1].get("status") == "bounded_window" and
                    not audits[-1].get("has_more"))
    failed = any(c.get("status") != "bounded_window" for c in audits) or any(
        str(c.get("check", "")).endswith(("_audit_record", "_audit_pagination")) for c in checks)
    if complete and not failed:
        return {"available": True, "reason": "audit_read_succeeded_within_retention"}
    reason = ("offline" if offline else "audit_not_requested" if not requested else
              "audit_incomplete" if audits and any(c.get("status") == "bounded_window" for c in audits)
              else "audit_unavailable")
    return {"available": False, "reason": reason, "checks": audits}


def estimate_public_origin(repo_path, snapshot, metadata, evidence, checks, *, git, audit):
    """Collect bounded local signals and score available API/evidence observations."""
    signals = []
    is_gitlab = metadata.get("provider") == "gitlab" or any(
        str(c.get("check", "")).startswith("gitlab_") for c in checks)

    def add(key, group, weight, detected, value, source, explanation):
        signals.append({"signal": key, "group": group, "weight": weight,
                        "status": "unavailable" if detected is None else "detected" if detected else "not_detected",
                        "value": value, "source": source, "explanation": explanation,
                        "raw_points": weight if detected else 0, "contribution_points": 0})

    def matches(*kinds):
        return [e for e in evidence if e.get("kind") in kinds]

    def trace(key, weight, kinds, explanation):
        found = matches(*kinds)
        add(key, "public_trace", weight, True if found else None, found[:10],
            "provenance_evidence", explanation)

    visibility_known = metadata.get("available") and (
        metadata.get("visibility") in {"public", "private", "internal"} or metadata.get("is_private") is True)
    current = matches("currently_public")
    add("current_public_visibility", "public_trace", 95,
        True if current else metadata.get("visibility") == "public" if visibility_known else None,
        metadata.get("visibility"), "provider_metadata",
        "Current public access strongly indicates exposure; current private access says nothing about the past.")
    trace("historical_public_trace", 85, ["historical_public_repository"],
          "Historical public records are strong leads; name-only matches can refer to a reused name.")
    # Name-only historical observations receive less weight than stable-ID matches.
    if signals[-1]["status"] == "detected" and not any(
            e.get("strength") == "confirmed" for e in matches("historical_public_repository")):
        signals[-1].update(weight=40, raw_points=40)
    elif signals[-1]["status"] == "unavailable" and any(
            c.get("check") == "github_recent_events" and c.get("status") == "bounded_window" for c in checks):
        signals[-1]["status"] = "not_detected"
    trace("public_commit_match", 75, ["public_commit_match"],
          "An exact public commit match may be shared dependency/template history, not publication of this repository.")
    if is_gitlab:
        trace("archived_origin_snapshot_match", 75, ["archive_origin_snapshot_match"],
              "A dated archive visit to the original URL with matching Git history is a strong historical lead, but does not record the visibility-setting change.")
    trace("public_fork_ancestry", 60, ["public_fork_ancestry"],
          "A provider-reported public ancestor indicates public-origin code, not a visibility transition.")
    if signals[-1]["status"] == "unavailable" and metadata.get("is_fork") is False:
        signals[-1]["status"] = "not_detected"
    trace("supplied_reference_match", 35, ["reference_commit_match", "reference_source_match"],
          "A matching supplied mirror/reference needs independent verification of its public origin.")

    search_checks = [c for c in checks if c.get("check") == "public_commit_search"]
    # A successful negative sample is an observation, never a privacy guarantee.
    search_signal = next(s for s in signals if s["signal"] == "public_commit_match")
    if search_signal["status"] == "unavailable" and search_checks and all(
            c.get("status") == 200 and c.get("incomplete_results") is False for c in search_checks):
        search_signal["status"] = "not_detected"

    add("fork_relationship", "relationship", 8,
        metadata.get("is_fork") if isinstance(metadata.get("is_fork"), bool) else None,
        metadata.get("is_fork"), "provider_metadata",
        "Private forks are possible, so a fork relationship alone is a weak indicator.")
    for field, weight in (("stars", 2), ("subscribers", 1), ("forks", 3)):
        value = metadata.get(field)
        known = isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
        add(field, "engagement", weight, value > 0 if known else None, value if known else None,
            "provider_metadata", "Nonzero engagement is weak: private repositories also have collaborators and forks.")
    links = matches("repository_links", "additional_remote")
    add("upstream_links_or_remotes", "documentation", 3, bool(links) if snapshot.get("is_git_root") else None,
        links[:10], "local_git_and_files", "Links and extra remotes suggest possible upstreams; they do not verify a public mirror.")
    deleted = matches("deleted_license_history")
    add("deleted_license", "documentation", 6, bool(deleted) if snapshot.get("history_readable") else None,
        deleted[:3], "local_git", "License removal may be routine maintenance; it is only a weak provenance lead.")

    root = Path(repo_path)
    license_files, license_readable = [], False
    try:
        for path in root.iterdir():
            if re.fullmatch(r"(?:licen[sc]e|copying)(?:[._-].*)?", path.name, re.I):
                if not path.is_symlink() and path.is_file() and path.stat().st_size <= 2 * 1024 * 1024:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    if re.search(r"MIT License|Apache License|GNU (?:GENERAL|LESSER|AFFERO)|BSD (?:[23]-Clause|License)|"
                                 r"SPDX-License-Identifier:\s*(?:MIT|Apache-2\.0|BSD-[23]-Clause|(?:A|L)?GPL-[123]\.0)\b", text, re.I):
                        license_files.append(path.name)
        license_readable = True
    except OSError:
        pass
    add("open_source_license_artifact", "documentation", 4,
        bool(license_files) if license_readable else None, license_files, "local_files",
        "An open-source license artifact may cover third-party material in a private project.")

    readme_log = None
    authors = None
    if snapshot.get("is_git_root"):
        readme_log = git(repo_path, "log", "--all", "--max-count=30", "--format=%H", "--diff-filter=D", "--name-only", "--",
                         ":(icase,glob)readme*", ":(icase,glob)**/readme*")
        authors = git(repo_path, "log", "--all", "HEAD", "--max-count=1000", "--format=%ae")
    add("deleted_readme", "documentation", 2, bool(readme_log) if readme_log is not None else None,
        readme_log[:4000] if readme_log else None, "local_git",
        "README deletions can hide attribution but are also ordinary documentation maintenance.")

    history_complete = bool(snapshot.get("history_readable") and not snapshot.get("shallow") and
                            not snapshot.get("replace_refs_present") and not snapshot.get("grafts_present"))
    files = git(repo_path, "ls-files") if snapshot.get("is_git_root") else None
    source_files = sum(Path(f).suffix.lower() in {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".cs", ".rb", ".php"}
                       and not any(p in {"vendor", "node_modules", "third_party", "generated"} for p in Path(f).parts)
                       for f in (files or "").splitlines())
    count = snapshot.get("reachable_commit_count", 0)
    add("large_tree_short_history", "history", 4,
        source_files >= 100 and 1 <= count <= 5 if history_complete and files is not None else None,
        {"source_files": source_files if files is not None else None, "commits": count}, "local_git",
        "At least 100 tracked source files with 1-5 commits can indicate an import or squash; it is not proof of scrubbing.")
    add("contributor_metadata", "context", 0, bool(authors) if authors is not None else None,
        {"distinct_author_emails_in_sample": len(set(authors.splitlines())) if authors else None,
         "sample_limit": 1000}, "local_git",
        "Contributor counts and personal email domains do not establish public origin; no points are assigned.")
    add("clone_history", "context", 0, None, None, "not_collected",
        "A clone does not retain earlier server visibility or other clones. Restricted traffic data is not lifetime history.")

    # Correlated observations within a group contribute only the strongest one,
    # except engagement, whose three small weights add up to its six-point cap.
    group_points = {}
    for group, cap in GROUP_CAPS.items():
        members = [s for s in signals if s["group"] == group and s["raw_points"]]
        if group == "engagement":
            for s in members:
                s["contribution_points"] = s["raw_points"]
        elif members:
            winner = max(members, key=lambda s: s["raw_points"])
            winner["contribution_points"] = min(cap, winner["raw_points"])
        group_points[group] = min(cap, sum(s["contribution_points"] for s in members))
    total = sum(group_points.values())
    scored = [s for s in signals if s["weight"] > 0]
    observed = sum(s["status"] != "unavailable" for s in scored)
    return {"status": "ESTIMATE", "label": "Heuristic estimate, not a confirmed finding",
            "model_version": MODEL_VERSION + "-gitlab-public-v1" if is_gitlab else MODEL_VERSION,
            "likelihood_percent": min(99, total) if observed else None,
            "is_calibrated_probability": False, "audit": audit,
            "formula": "min(99, sum(group_points)); strongest signal per group, engagement sums up to 6",
            "group_caps": GROUP_CAPS, "group_points": group_points,
            "uncapped_points": total, "cap_adjustment_points": min(99, total) - total,
            "coverage": {"observed_scored_signals": observed, "total_scored_signals": len(scored),
                         "unavailable_signals": [s["signal"] for s in signals if s["status"] == "unavailable"]},
            "signals": signals,
            "limitations": ["Weights are assumptions without empirical calibration; this percentage is an exposure index, not a statistical probability.",
                            "0% means no weighted indicators observed, not a 0% chance of past publication. Missing signals never clear a repository.",
                            "Public-origin code, a public ancestor, and publication of this exact repository are different claims.",
                            ("GitLab public candidate and archive checks are bounded; no platform-wide GitLab commit search is performed."
                             if is_gitlab else "No global mirror/web search is performed; public traces depend on existing evidence and optional commit search."),
                            "Local history and attribution may be incomplete or edited; absence of findings cannot verify privacy."]}
