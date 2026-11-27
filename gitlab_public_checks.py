"""Bounded, anonymous GitLab Free public-reference and archive checks.

These observations can establish shared public code or an archived origin visit,
but cannot establish a repository visibility-setting transition.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib import parse

from provider_provenance import ScopedClient, identify_repository


MAX_CANDIDATES = 5
MAX_SHAS = 5
MAX_LINKS = 6
MAX_ARCHIVE_ORIGINS = 4
MAX_ARCHIVE_VISITS = 10
MAX_ARCHIVE_SNAPSHOTS = 6
LOCAL_LINK_FILES = ("README.md", "README.rst", "README", "package.json", "pyproject.toml", "Cargo.toml", "go.mod", ".gitmodules")
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", re.I)


def _sample_shas(commits: Iterable[str]) -> List[str]:
    ordered = list(dict.fromkeys(s.lower() for s in commits if isinstance(s, str) and SHA.fullmatch(s)))
    return [ordered[round(i * (len(ordered) - 1) / max(1, min(len(ordered), MAX_SHAS) - 1))]
            for i in range(min(len(ordered), MAX_SHAS))]


def _linked_names(repo_path: str, snapshot: Dict[str, Any], identity: Dict[str, Any]) -> List[str]:
    """Only extract references on the already identified GitLab instance."""
    base = identity["instance_url"]
    names = []
    for remote in snapshot.get("remotes", []):
        candidate = identify_repository(remote.get("url", ""), "gitlab", base)
        if candidate:
            names.append(candidate["repository_name"])
    for filename in LOCAL_LINK_FILES:
        path = Path(repo_path, filename)
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for url in re.findall(r"https?://[^\s<>\"'()\[\]{}]+", content)[:100]:
            candidate = identify_repository(url.rstrip(".,;"), "gitlab", base)
            if candidate:
                names.append(candidate["repository_name"])
    return list(dict.fromkeys(names))[:MAX_LINKS]


def _status(result: Any) -> Any:
    return result.get("status") if isinstance(result, dict) else "invalid_response"


def _valid_candidate(item: Any, base: str) -> bool:
    if not isinstance(item, dict) or item.get("visibility") != "public" or not isinstance(item.get("id"), int):
        return False
    name = item.get("path_with_namespace")
    identity = identify_repository(base + "/" + name, "gitlab", base) if isinstance(name, str) else None
    return bool(identity and identity["repository_name"] == name)


def collect_gitlab_public_matches(repo_path: str, snapshot: Dict[str, Any], identity: Dict[str, Any],
                                  commits: Iterable[str], *, original_name: Optional[str] = None,
                                  client: Optional[Any] = None) -> Dict[str, Any]:
    """Search public candidates and verify exact SHAs within those projects."""
    result: Dict[str, Any] = {"checks": [], "evidence": [], "limitations": []}
    checks = result["checks"]
    base = identity["instance_url"]
    client = client or ScopedClient(base, None, timeout=5)
    canonical_name = identity["repository_name"]
    submitted_name = original_name or canonical_name
    linked = _linked_names(repo_path, snapshot, identity)
    search_terms = list(dict.fromkeys(n.rsplit("/", 1)[-1] for n in
                                      (submitted_name, canonical_name) if n))
    candidates: Dict[int, Dict[str, Any]] = {}

    # A direct URL can refer to a mirror whose name does not resemble the target.
    for name in linked:
        if name.lower() in {submitted_name.lower(), canonical_name.lower()}:
            continue
        response = client.get("/api/v4/projects/" + parse.quote(name, safe=""), authenticated=False)
        checks.append({"check": "gitlab_public_link", "repository_name": name, "status": _status(response)})
        item = response.get("data") if isinstance(response, dict) else None
        if _status(response) == 200 and _valid_candidate(item, base):
            candidates[item["id"]] = item
        if len(candidates) >= MAX_CANDIDATES:
            break

    for search_term in search_terms:
        if len(candidates) >= MAX_CANDIDATES:
            break
        query = parse.urlencode({"search": search_term, "visibility": "public", "per_page": 20})
        response = client.get("/api/v4/projects?" + query, authenticated=False)
        items = response.get("data") if isinstance(response, dict) else None
        checks.append({"check": "gitlab_public_project_search", "term": search_term,
                       "status": _status(response), "results": len(items) if isinstance(items, list) else None,
                       "has_more": bool(response.get("next_url")) if isinstance(response, dict) else False})
        if _status(response) == 200 and isinstance(items, list):
            for item in items:
                if not _valid_candidate(item, base):
                    continue
                candidate_name = item.get("path_with_namespace")
                if not isinstance(candidate_name, str):
                    continue
                # Prefer exact repo names; other search hits may only match descriptions.
                if candidate_name.rsplit("/", 1)[-1].lower() != search_term.lower():
                    continue
                candidates[item["id"]] = item
                if len(candidates) >= MAX_CANDIDATES:
                    break
        if isinstance(response, dict) and response.get("next_url"):
            result["limitations"].append("GitLab public project search stopped after one page; further candidates may exist.")

    shas = _sample_shas(commits)
    for project_id, item in list(candidates.items())[:MAX_CANDIDATES]:
        candidate_name = item.get("path_with_namespace")
        if (project_id == identity.get("repository_id") or
                isinstance(candidate_name, str) and candidate_name.lower() in {submitted_name.lower(), canonical_name.lower()}):
            continue
        matched = []
        failed = False
        for sha in shas:
            response = client.get(f"/api/v4/projects/{project_id}/repository/commits/{sha}", authenticated=False)
            data = response.get("data") if isinstance(response, dict) else None
            status = _status(response)
            if status == 200 and isinstance(data, dict) and str(data.get("id", "")).lower() == sha:
                matched.append(sha)
            elif status not in {200, 404}:
                failed = True
                break
        checks.append({"check": "gitlab_candidate_commit_verification", "repository_id": project_id,
                       "repository_name": candidate_name, "sampled_shas": len(shas),
                       "matched_shas": len(matched), "status": "partial" if failed else "complete"})
        if matched:
            result["evidence"].append({"kind": "public_commit_match", "source": "gitlab_anonymous_candidate_lookup",
                                       "strength": "code_match", "repository_id": project_id,
                                       "repository_name": candidate_name,
                                       "repository_url": base + "/" + candidate_name if isinstance(candidate_name, str) else None,
                                       "shas": matched,
                                       "independently_fetched": True})
    if not shas:
        checks.append({"check": "gitlab_candidate_commit_verification", "status": "local_history_unavailable"})
    result["limitations"].append("GitLab candidate search samples at most five public projects and five local commits; a miss never proves privacy.")
    return result


def collect_gitlab_archive_matches(identity: Dict[str, Any], commits: Iterable[str], *,
                                   original_name: Optional[str] = None,
                                   client: Optional[Any] = None) -> Dict[str, Any]:
    """Verify matching Git branch tips in dated Software Heritage origin visits."""
    result: Dict[str, Any] = {"checks": [], "evidence": [], "limitations": []}
    checks = result["checks"]
    archive = client or ScopedClient("https://archive.softwareheritage.org", None, timeout=5)
    base = identity["instance_url"]
    # SWH GitLab origins normally use .git; the suffixless form also occurs.
    names = list(dict.fromkeys(n for n in (original_name, identity["repository_name"]) if n))
    origins = [base + "/" + name + suffix for name in names for suffix in (".git", "")]
    local_shas = {s.lower() for s in commits if isinstance(s, str) and SHA.fullmatch(s)}
    if not local_shas:
        checks.append({"check": "gitlab_software_heritage_snapshot", "status": "local_history_unavailable"})
        return result
    snapshot_lookups = 0
    for origin in origins[:MAX_ARCHIVE_ORIGINS]:
        if snapshot_lookups >= MAX_ARCHIVE_SNAPSHOTS:
            break
        path = "/api/1/origin/" + parse.quote(origin, safe=":/") + "/visits/?per_page=5"
        seen, visits_read, found = set(), 0, False
        while path and path not in seen and visits_read < MAX_ARCHIVE_VISITS:
            seen.add(path)
            response = archive.get(path, authenticated=False)
            visits = response.get("data") if isinstance(response, dict) else None
            checks.append({"check": "gitlab_software_heritage_visits", "origin_url": origin,
                           "status": _status(response), "visits": len(visits) if isinstance(visits, list) else None})
            if _status(response) != 200 or not isinstance(visits, list):
                path = None
                break
            remaining = MAX_ARCHIVE_VISITS - visits_read
            visits_read += min(len(visits), remaining)
            for visit in visits[:remaining]:
                if not isinstance(visit, dict) or visit.get("origin") != origin or visit.get("status") != "full" or visit.get("type") != "git":
                    continue
                try:
                    visited_at = dt.datetime.fromisoformat(str(visit.get("date", "")).replace("Z", "+00:00"))
                    if visited_at.tzinfo is None:
                        continue
                except ValueError:
                    continue
                snapshot_id = visit.get("snapshot")
                if not isinstance(snapshot_id, str) or not SHA.fullmatch(snapshot_id):
                    continue
                if snapshot_lookups >= MAX_ARCHIVE_SNAPSHOTS:
                    break
                snapshot_lookups += 1
                snapshot = archive.get("/api/1/snapshot/" + snapshot_id + "/?branches_count=1000", authenticated=False)
                data = snapshot.get("data") if isinstance(snapshot, dict) else None
                branches = data.get("branches") if isinstance(data, dict) else None
                matches = []
                if _status(snapshot) == 200 and isinstance(branches, dict) and str(data.get("id", "")).lower() == snapshot_id.lower():
                    matches = sorted({str(branch.get("target", "")).lower() for branch in branches.values()
                                      if isinstance(branch, dict) and branch.get("target_type") == "revision" and
                                      str(branch.get("target", "")).lower() in local_shas})
                checks.append({"check": "gitlab_software_heritage_snapshot", "origin_url": origin,
                               "visit_date": visit.get("date"), "snapshot_id": snapshot_id,
                               "status": _status(snapshot), "matched_shas": len(matches),
                               "has_more_branches": bool(snapshot.get("next_url")) if isinstance(snapshot, dict) else False})
                if isinstance(snapshot, dict) and snapshot.get("next_url") and not matches:
                    result["limitations"].append("Software Heritage snapshot branches were truncated; a matching branch may be omitted.")
                if matches:
                    result["evidence"].append({"kind": "archive_origin_snapshot_match", "source": "software_heritage_anonymous_api",
                                               "strength": "code_match", "origin_url": origin,
                                               "visit_date": visited_at.isoformat(), "snapshot_id": snapshot_id,
                                               "snapshot_url": "https://archive.softwareheritage.org/api/1/snapshot/" + snapshot_id + "/",
                                               "shas": matches, "independently_fetched": True})
                    found = True
                    break
            path = response.get("next_url") if isinstance(response, dict) else None
            if found:
                break
        if found:
            break
        if path in seen:
            result["limitations"].append("Software Heritage returned a repeated pagination link; older visits were not examined.")
        elif path:
            result["limitations"].append("Software Heritage visits exceeded the ten-visit limit; older visits were not examined.")
    if snapshot_lookups >= MAX_ARCHIVE_SNAPSHOTS and not result["evidence"]:
        result["limitations"].append("Software Heritage snapshot checks reached the six-snapshot limit; more visits may match.")
    result["limitations"].append("Software Heritage coverage is incomplete; a missing visit or branch tip does not establish lifetime privacy.")
    return result
