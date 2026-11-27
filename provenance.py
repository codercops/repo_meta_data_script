"""Evidence-based public-origin checks. Absence of evidence never proves privacy.

GitLab Free checks send bounded commit hashes anonymously to candidate projects.
GitHub public commit search is opt-in; source text and local reference contents
are never uploaded.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import warnings
from typing import Any, Dict, Iterable, List, Optional
from urllib import error, parse, request
from provider_provenance import collect_provider, identify_repository, match_audit, normalize_audit
from gitlab_public_checks import collect_gitlab_archive_matches, collect_gitlab_public_matches
from heuristic_provenance import audit_availability, estimate_public_origin
# Personal-account browser Security-log collection is intentionally disabled.
# Keep github_personal_security_log.py as dormant reference code; organization
# audit reads below remain active.


LIMITATIONS = [
    "No search or audit-log window can prove a repository was always private.",
    "Git dates, authors, remotes and local evidence files can be edited or fabricated.",
    "Deleted repositories, detached forks, renames, transfers and rewritten history can hide origins.",
    "A shared commit/file can be a dependency or template; it does not establish ownership or copying direction.",
    "Imported records and reference repositories require independent verification of their source.",
]
SOURCE_EXTENSIONS = set(".py .js .ts .jsx .tsx .go .rs .java .c .cpp .cc .h .hpp .cs .rb .php .swift .kt .scala .lua .ex .exs .sh .sql .vue .svelte .dart .m .mm".split())
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "vendors", "third_party", "third-party", "venv", ".venv", "env", "build", "dist", "generated", "__pycache__", "coverage", "outputs", "cloned_repos"}
SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$", re.I)
GITHUB_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_EVIDENCE = 500
MAX_FILE_BYTES = 2 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_url(value: str) -> str:
    """Retain host/path only; never persist URL credentials, queries or fragments."""
    try:
        parsed = parse.urlsplit(value)
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname
            if parsed.port:
                host += ":" + str(parsed.port)
            return parse.urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        pass
    return re.sub(r"([a-z]+://)[^/@\s]+@", r"\1", value, flags=re.I).split("?", 1)[0].split("#", 1)[0]


def github_name(value: str) -> Optional[str]:
    """Parse an exact github.com host, including SCP/SSH and dotted repo names."""
    if not value:
        return None
    if re.match(r"^(?:[^@/]+@)?github\.com:", value, re.I):
        path = value.split(":", 1)[1]
    else:
        try:
            url = parse.urlsplit(value)
            if (url.hostname or "").lower() != "github.com":
                return None
            path = url.path.strip("/")
        except ValueError:
            return None
    parts = path.strip("/").split("/")
    if len(parts) < 2:
        return None
    name = "/".join(parts[:2])
    if name.endswith(".git"):
        name = name[:-4]
    return name if GITHUB_NAME.fullmatch(name) and all(p not in {".", ".."} for p in name.split("/")) else None


def git(repo: str, *args: str, timeout: int = 60) -> Optional[str]:
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    try:
        completed = subprocess.run(["git", "--no-pager", *args], cwd=repo, env=env,
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=timeout)
        return completed.stdout.strip() if completed.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def snapshot_repository(repo: str, target: str) -> Dict[str, Any]:
    """Capture redacted provenance before any caller changes Git configuration."""
    root = git(repo, "rev-parse", "--show-toplevel")
    is_root = bool(root and os.path.normcase(os.path.realpath(root)) == os.path.normcase(os.path.realpath(repo)))
    remotes = []
    if is_root:
        for name in (git(repo, "remote") or "").splitlines():
            urls = git(repo, "config", "--get-all", f"remote.{name}.url") or ""
            for url in urls.splitlines():
                remotes.append({"name": name, "url": safe_url(url)})
    origin = next((r["url"] for r in remotes if r["name"] == "origin"), "")
    name = github_name(target) or github_name(origin)
    raw = git(repo, "rev-list", "--all", "HEAD", timeout=120) if is_root else None
    commits = list(dict.fromkeys(line for line in (raw or "").splitlines() if SHA.fullmatch(line)))
    replacements = git(repo, "for-each-ref", "--format=%(refname)", "refs/replace") if is_root else None
    shallow = git(repo, "rev-parse", "--is-shallow-repository") if is_root else None
    return {
        "is_git_root": is_root, "target": safe_url(target), "remotes": remotes,
        "github_name": name, "head": git(repo, "rev-parse", "HEAD") if is_root else None,
        "reachable_commit_count": len(commits), "commits": commits,
        "history_readable": raw is not None, "shallow": shallow == "true",
        "replace_refs_present": bool(replacements),
        "grafts_present": bool(git(repo, "rev-parse", "--git-path", "info/grafts") and
                               Path(repo, git(repo, "rev-parse", "--git-path", "info/grafts")).is_file()) if is_root else False,
    }


class GitHubClient:
    """Bounded, read-only requests; no implicit retries or credentialed redirects."""
    def __init__(self, token: Optional[str] = None):
        self.token = token

    def get(self, path: str, authenticated: bool = True) -> Dict[str, Any]:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "repo-provenance-analyzer",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if authenticated and self.token:
            headers["Authorization"] = "Bearer " + self.token
        # Follow renames only within api.github.com. Never forward a token to
        # another host through redirects or pagination links.
        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        for redirect in range(4):
            if not path.startswith("/") or path.startswith("//"):
                return {"status": "unsafe_api_path", "data": None}
            try:
                req = request.Request("https://api.github.com" + path, headers=headers)
                with request.build_opener(NoRedirect()).open(req, timeout=20) as response:
                    raw = response.read(8 * 1024 * 1024 + 1)
                    if len(raw) > 8 * 1024 * 1024:
                        return {"status": "response_too_large", "data": None}
                    link = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get("Link", ""))
                    return {"status": response.status, "data": json.loads(raw),
                            "next_path": _api_path(link.group(1)) if link else None}
            except error.HTTPError as exc:
                new_path = _api_path(exc.headers.get("Location", "")) if exc.headers else None
                if exc.code in {301, 302, 307, 308} and new_path and redirect < 3:
                    path = new_path
                    continue
                return {"status": exc.code, "data": None}
            except (OSError, ValueError):
                # Never include exception strings containing URLs, headers or tokens.
                return {"status": "network_or_json_error", "data": None}
        return {"status": "redirect_limit", "data": None}


def _api_path(url: str) -> Optional[str]:
    try:
        parts = parse.urlsplit(url)
        if (parts.scheme == "https" and parts.hostname == "api.github.com" and
                not parts.username and not parts.password and parts.port in {None, 443}):
            return parts.path + ("?" + parts.query if parts.query else "")
    except ValueError:
        pass
    return None


def _metadata(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "available": True, "provider": "github", "repository_id": raw.get("id"),
        "full_name": raw.get("full_name"), "is_private": raw.get("private") if isinstance(raw.get("private"), bool) else None,
        "visibility": raw.get("visibility"), "is_fork": raw.get("fork"),
        "created_at": raw.get("created_at"), "pushed_at": raw.get("pushed_at"),
        "default_branch": raw.get("default_branch"), "stars": raw.get("stargazers_count"),
        "forks": raw.get("forks_count"), "open_issues": raw.get("open_issues_count"),
        "subscribers": raw.get("subscribers_count"), "description": raw.get("description"),
        "language": raw.get("language"), "size_kb": raw.get("size"),
        "license": (raw.get("license") or {}).get("spdx_id"),
        "owner": (raw.get("owner") or {}).get("login"),
        "owner_type": (raw.get("owner") or {}).get("type"), "topics": raw.get("topics", []),
    }


def _event_identity(event: Dict[str, Any]) -> tuple:
    repo = event.get("repo") or event.get("repository") or {}
    if isinstance(repo, dict):
        return repo.get("id") or event.get("repo_id") or event.get("repository_id"), repo.get("name") or repo.get("full_name")
    return event.get("repo_id") or event.get("repository_id"), repo


def _event_time(value: Any) -> Optional[str]:
    try:
        if isinstance(value, (int, float)):
            return dt.datetime.fromtimestamp(value / 1000, dt.timezone.utc).isoformat()
        date = dt.datetime.fromisoformat(str(value).replace(" UTC", "+00:00").replace("Z", "+00:00"))
        return date.replace(tzinfo=date.tzinfo or dt.timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _payload(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return {}
    return payload if isinstance(payload, dict) else {}


def _public_event_shas(event: Dict[str, Any]) -> List[str]:
    payload = _payload(event)
    candidates = [payload.get("head"), payload.get("before")]
    candidates += [c.get("sha") for c in (payload.get("commits") or []) if isinstance(c, dict)]
    return [s.lower() for s in candidates if isinstance(s, str) and SHA.fullmatch(s) and set(s) != {"0"}]


def _records(path: str) -> Iterable[Dict[str, Any]]:
    """Read JSON arrays, API JSON objects, or streaming JSONL (including .gz)."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8-sig") as handle:
        first = ""
        while not first:
            char = handle.read(1)
            if not char:
                return
            if not char.isspace():
                first = char
        handle.seek(0)
        if first == "[":
            # JSONL is preferable for large archive exports.
            raw = handle.read(64 * 1024 * 1024 + 1)
            if len(raw) > 64 * 1024 * 1024:
                raise ValueError("JSON array exceeds 64 MiB; use JSONL")
            values = json.loads(raw)
            for value in values:
                if not isinstance(value, dict):
                    raise ValueError("Evidence records must be objects")
                yield value
        else:
            for line in handle:
                if line.strip():
                    try:
                        value = json.loads(line)
                    except ValueError:
                        if line.strip() != "{":
                            raise
                        rest = handle.read(64 * 1024 * 1024 + 1)
                        if len(rest) > 64 * 1024 * 1024:
                            raise ValueError("JSON object exceeds 64 MiB; use JSONL")
                        value = json.loads(line + rest)
                    if not isinstance(value, dict):
                        raise ValueError("Evidence records must be objects")
                    yield value


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_manifest(repo: str, max_files: int = 20000) -> Dict[str, Any]:
    """Read local authored-looking text without following symlinks/junctions."""
    repo = str(Path(repo).resolve())
    files, skipped, seen = [], 0, 0
    root_path = Path(repo).resolve()
    for root, dirs, names in os.walk(repo, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d.lower() not in EXCLUDED_DIRS and
                         not Path(root, d).is_symlink() and
                         not getattr(os.path, "isjunction", lambda p: False)(Path(root, d)))
        for name in sorted(names):
            path = Path(root, name)
            if path.suffix.lower() not in SOURCE_EXTENSIONS or name.endswith((".min.js", ".min.css")):
                continue
            seen += 1
            if seen > max_files:
                return {"files": files, "skipped": skipped, "truncated": True}
            try:
                if path.is_symlink() or root_path not in path.resolve().parents or not 200 <= path.stat().st_size <= MAX_FILE_BYTES:
                    skipped += 1
                    continue
                with path.open("rb") as handle:
                    raw = handle.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                if b"\0" in raw:
                    skipped += 1
                    continue
                text = raw.decode("utf-8")
                if "generated" in "\n".join(text.splitlines()[:3]).lower():
                    skipped += 1
                    continue
                # Normalized exact text detects renamed files and changed line endings.
                normalized = "\n".join(line.rstrip() for line in text.splitlines()).strip()
                files.append({"path": path.relative_to(root_path).as_posix(),
                              "sha256": hashlib.sha256(raw).hexdigest(),
                              "normalized_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
                              "bytes": len(raw)})
            except (OSError, UnicodeError, ValueError):
                skipped += 1
    return {"files": files, "skipped": skipped, "truncated": False}


def build_archive_query(names: List[str], repository_id: Any, year: int) -> str:
    """Generate one bounded calendar-year BigQuery query; never execute paid jobs."""
    if not 2011 <= year <= dt.datetime.now(dt.timezone.utc).year:
        raise ValueError("Archive year must be between 2011 and the current UTC year")
    literals = ", ".join("'" + name.lower() + "'" for name in names if GITHUB_NAME.fullmatch(name))
    filters = [f"LOWER(repo.name) IN ({literals})"] if literals else []
    if str(repository_id).isdigit():
        filters.insert(0, f"CAST(repo.id AS STRING) = '{repository_id}'")
    where = " OR ".join(filters) or "FALSE"
    return ("-- Review estimated bytes/cost and set maximum_bytes_billed before running.\n"
            "-- Export raw rows as JSONL, then pass --evidence (standalone) or --provenance-evidence.\n"
            "-- Repeat for every relevant year, former owner/name and provider. No results prove nothing.\n"
            "SELECT id, type, repo, public, created_at, payload\n"
            "FROM `githubarchive.day.*`\n"
            f"WHERE _TABLE_SUFFIX BETWEEN '{year}0101' AND '{year}1231'\n"
            f"  AND public = TRUE AND ({where})\nORDER BY created_at;\n")


def analyze_provenance(
    repo_path: str, target: Optional[str] = None, *, github_token: Optional[str] = None,
    provider_metadata: Optional[Dict[str, Any]] = None, offline: bool = False,
    evidence_paths: Optional[List[str]] = None, public_reference_paths: Optional[List[str]] = None,
    audit_log: bool = False, search_public_commits: bool = False, max_search_commits: int = 8,
    client: Optional[Any] = None,
    gitlab_token: Optional[str] = None, bitbucket_token: Optional[str] = None,
    provider: Optional[str] = None, provider_instance_url: Optional[str] = None,
    atlassian_org_id: Optional[str] = None, atlassian_admin_token: Optional[str] = None,
    provider_client: Optional[Any] = None, admin_client: Optional[Any] = None,
    gitlab_public_client: Optional[Any] = None, software_heritage_client: Optional[Any] = None,
    personal_security_profile: Optional[str] = None,  # Deprecated; ignored.
) -> Dict[str, Any]:
    """Return auditable observations and a conservative procurement recommendation."""
    snapshot = snapshot_repository(repo_path, target or repo_path)
    commits = set(snapshot.pop("commits"))
    name = snapshot["github_name"]
    metadata = dict(provider_metadata or {})
    origin = next((r["url"] for r in snapshot["remotes"] if r["name"] == "origin"), "")
    native_identity = identify_repository(target or "", provider, provider_instance_url) or identify_repository(origin, provider, provider_instance_url)
    submitted_gitlab_name = native_identity["repository_name"] if native_identity and native_identity["provider"] == "gitlab" else None
    evidence: List[Dict[str, Any]] = []
    checks: List[Dict[str, Any]] = []
    limitations = list(LIMITATIONS)
    sources: List[Dict[str, Any]] = []
    client = client or GitHubClient(github_token)
    repo_id = None
    observed_at = utc_now()
    finding_flags = {"exposure": False, "code_match": False, "transition": False}

    def add(kind: str, source: str, strength: str, **detail: Any) -> None:
        finding_flags["exposure"] |= strength == "confirmed"
        finding_flags["code_match"] |= strength == "code_match"
        finding_flags["transition"] |= kind == "public_to_private_transition" and strength == "confirmed"
        finding = {"kind": kind, "source": source, "strength": strength, **detail}
        if len(evidence) < MAX_EVIDENCE:
            evidence.append(finding)
        else:
            # A flood of weak leads must not evict stronger evidence or change the decision.
            if strength == "confirmed":
                replace = next((i for i, e in enumerate(evidence) if e["strength"] != "confirmed"), None)
                if replace is None and kind == "public_to_private_transition":
                    replace = next((i for i, e in enumerate(evidence) if e["kind"] != kind), None)
                if replace is not None:
                    evidence[replace] = finding
            if "Evidence details capped at 500 records." not in limitations:
                limitations.append("Evidence details capped at 500 records.")

    def observe_event(event: Dict[str, Any], source: str, authenticated_source: bool = False) -> bool:
        event_id, event_name = _event_identity(event)
        # GitHub IDs are never compared with another provider's numeric IDs.
        github_id = repo_id if name else None
        same_id = github_id is not None and event_id is not None and str(event_id) == str(github_id)
        id_conflict = github_id is not None and event_id is not None and not same_id
        same_name = bool(event_name and name and str(event_name).lower() == name.lower())
        # Repository names can be reused. A conflicting immutable ID takes priority.
        identity = "repository_id" if same_id else "name_only" if same_name and not id_conflict else None
        timestamp = _event_time(event.get("created_at") or event.get("@timestamp"))
        public = event.get("public") is True
        is_audit = event.get("action") in {"repo.access", "repo.create"}
        audit_public = is_audit and (event.get("previous_visibility") == "public" or
                                    event.get("visibility") == "public" or event.get("public_repo") is True)
        # A public flag on an unrelated record is insufficient; require an event type.
        if identity and timestamp and ((public and str(event.get("type", "")).endswith("Event")) or audit_public):
            strength = "confirmed" if same_id else "lead"
            add("historical_public_repository", source, strength,
                timestamp=timestamp, repository_id=event_id, repository_name=event_name,
                identity_match=identity, event_type=event.get("type") or event.get("action"),
                event_id=event.get("id") or event.get("_document_id"),
                previous_visibility=event.get("previous_visibility"), visibility=event.get("visibility"),
                independently_fetched=authenticated_source)
            if is_audit and event.get("action") == "repo.access" and event.get("previous_visibility") == "public" and event.get("visibility") == "private":
                add("public_to_private_transition", source, strength, timestamp=timestamp,
                    repository_id=event_id, repository_name=event_name,
                    independently_fetched=authenticated_source)
        if public and timestamp and str(event.get("type", "")).endswith("Event"):
            matches = sorted(commits.intersection(_public_event_shas(event)))
            if matches:
                add("public_commit_match", source, "code_match", timestamp=timestamp,
                    repository_name=event_name, repository_id=event_id, shas=matches,
                    independently_fetched=authenticated_source)
        return bool(identity)

    def observe_native(event: Dict[str, Any], source: str, fetched: bool = False) -> bool:
        if not native_identity:
            return False
        identity_match = match_audit(event, native_identity)
        if not identity_match:
            return False
        timestamp = _event_time(event.get("timestamp"))
        old, new = event.get("previous_visibility"), event.get("visibility")
        detail = {key: event.get(key) for key in ("provider", "instance_url", "repository_id", "repository_name", "event_id", "action", "raw_event_sha256")}
        detail.update(timestamp=timestamp, previous_visibility=old, visibility=new,
                      identity_match=identity_match, independently_fetched=fetched)
        if timestamp and "public" in {old, new}:
            strength = "confirmed" if identity_match == "repository_id_and_instance" else "lead"
            add("historical_public_repository", source, strength, **detail)
            if old == "public" and new == "private":
                add("public_to_private_transition", source, strength, **detail)
        else:
            add("native_visibility_change_unresolved", source, "lead", **detail)
        return True

    def observe_imported(event: Dict[str, Any], source: str,
                         declared_provider: Optional[str] = None, instance: Optional[str] = None) -> int:
        # Optional envelopes bind instance-local IDs and retain the original raw
        # provider event format. Imports still require independent verification.
        declared_provider = event.get("provider", declared_provider) if "events" in event else declared_provider
        instance = event.get("instance_url", instance) if "events" in event else instance
        for key in ("events", "data", "entities", "values"):
            if isinstance(event.get(key), list):
                return sum(observe_imported(item, source, declared_provider, instance) for item in event[key] if isinstance(item, dict))
        if native_identity and (declared_provider is None or declared_provider == native_identity["provider"]):
            normalized = normalize_audit(event, native_identity["provider"], instance)
            if normalized:
                return int(observe_native(normalized, source))
        if declared_provider not in {None, "github"}:
            return 0
        return int(observe_event(event, source))

    def imported_record_count(event: Dict[str, Any]) -> int:
        for key in ("events", "data", "entities", "values"):
            if isinstance(event.get(key), list):
                return sum(imported_record_count(item) for item in event[key] if isinstance(item, dict))
        return 1

    raw_metadata: Dict[str, Any] = {}
    # These are investigative leads only. A license, link or upstream remote
    # does not establish that the submitted repository itself was ever public.
    for remote in snapshot["remotes"]:
        if remote["name"] != "origin":
            add("additional_remote", "local_git", "lead", name=remote["name"], url=remote["url"])
    if snapshot["is_git_root"]:
        deleted_licenses = git(repo_path, "log", "--all", "--max-count=30", "--diff-filter=D",
                               "--format=%H%x09%cI", "--name-only", "--",
                               ":(icase,glob)**/license*", ":(icase,glob)**/licence*", ":(icase,glob)**/copying*")
        if deleted_licenses:
            add("deleted_license_history", "local_git", "lead", log=deleted_licenses[:16000])
        candidates = []
        for filename in ("README.md", "README.rst", "README", "package.json", "pyproject.toml", "Cargo.toml", "go.mod", ".gitmodules"):
            path = Path(repo_path, filename)
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                for match in re.finditer(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", text):
                    candidate = github_name(match.group(0).rstrip("."))
                    if candidate and candidate.lower() != (name or "").lower():
                        candidates.append({"file": filename, "repository_name": candidate})
            except OSError:
                continue
        if candidates:
            add("repository_links", "local_files", "lead", candidates=candidates[:50])
    if native_identity:
        collected = collect_provider(
            native_identity, token=gitlab_token if native_identity["provider"] == "gitlab" else bitbucket_token,
            audit_log=audit_log, offline=offline, metadata=metadata,
            atlassian_org_id=atlassian_org_id, atlassian_token=atlassian_admin_token,
            client=provider_client, admin_client=admin_client,
        )
        native_identity = collected["identity"]
        repo_id = native_identity["repository_id"]
        metadata = collected["metadata"]
        checks.extend(collected["checks"])
        limitations.extend(collected["limitations"])
        if collected.get("public_observed"):
            add("currently_public", native_identity["provider"] + "_repository_api", "confirmed",
                timestamp=observed_at, repository_id=repo_id, instance_url=native_identity["instance_url"], independently_fetched=True)
        for ancestor in collected["public_ancestors"]:
            add("public_fork_ancestry", native_identity["provider"] + "_repository_api", "code_match", **ancestor)
        for event in collected["events"]:
            observe_native(event, native_identity["provider"] + "_audit_log", True)
    if name and not offline:
        result = client.get("/repos/" + name)
        checks.append({"check": "github_repository_metadata", "status": result["status"]})
        if result["status"] == 200 and isinstance(result.get("data"), dict):
            raw_metadata = result["data"]
            canonical = raw_metadata.get("full_name")
            if GITHUB_NAME.fullmatch(str(canonical or "")):
                name = canonical
            repo_id = raw_metadata.get("id")
            metadata = _metadata(raw_metadata)
        else:
            limitations.append("GitHub metadata unavailable; an HTTP 404 does not prove privacy or nonexistence.")
        # A separate anonymous request prevents a private token's access from being mistaken for public access.
        anonymous = client.get("/repos/" + name, authenticated=False)
        checks.append({"check": "github_anonymous_visibility", "status": anonymous["status"]})
        public_data = anonymous.get("data") or {}
        if anonymous["status"] == 200 and public_data.get("private") is False:
            public_id = public_data.get("id")
            if repo_id is None or str(public_id) == str(repo_id):
                repo_id = public_id
                metadata = _metadata(public_data)
                add("currently_public", "github_anonymous_api", "confirmed", timestamp=observed_at,
                    repository_id=public_id, repository_name=name, independently_fetched=True)
            else:
                add("repository_identity_conflict", "github_anonymous_api", "lead")
        if raw_metadata.get("private") is False and not any(e["kind"] == "currently_public" for e in evidence):
            add("currently_public", "github_repository_api", "confirmed", timestamp=observed_at,
                repository_id=repo_id, repository_name=name, independently_fetched=True)
        events_seen = 0
        for page in range(1, 4):
            result = client.get(f"/repos/{name}/events?per_page=100&page={page}")
            if result["status"] != 200 or not isinstance(result.get("data"), list):
                checks.append({"check": "github_recent_events", "status": result["status"], "records": events_seen})
                break
            for event in result["data"]:
                if isinstance(event, dict):
                    observe_event(event, "github_recent_events", True)
                    events_seen += 1
            if len(result["data"]) < 100 or page == 3:
                checks.append({"check": "github_recent_events", "status": "bounded_window", "records": events_seen})
                break
        limitations.append("Recent GitHub events are a bounded feed, not a lifetime visibility history.")
        for field in ("parent", "source"):
            ancestor = raw_metadata.get(field) or {}
            if ancestor.get("private") is False:
                add("public_fork_ancestry", "github_repository_api", "code_match",
                    repository_name=ancestor.get("full_name"), repository_id=ancestor.get("id"),
                    relationship=field, independently_fetched=True)
        if raw_metadata.get("fork") is True:
            add("fork_relationship", "github_repository_api", "lead", independently_fetched=True)
        if audit_log:
            owner_type = (raw_metadata.get("owner") or {}).get("type")
            if owner_type == "User":
                # No PAT audit endpoint exists for a personal account. Do not
                # launch a browser or mark the historical log as checked.
                checks.append({"check": "github_audit_log",
                               "status": "personal_account_provenance_only"})
                limitations.append("Personal GitHub Security log is not collected; historical exposure is assessed from public and local provenance signals.")
            elif owner_type != "Organization":
                checks.append({"check": "github_audit_log", "status": "owner_type_unknown"})
            elif not github_token:
                checks.append({"check": "github_audit_log", "status": "token_required"})
            else:
                # Optional permissioned endpoint. Always record retention and pagination limits.
                owner = name.split("/")[0]
                phrase = parse.quote(f"repo:{name} created:>=1970-01-01", safe="")
                audit_path = f"/orgs/{owner}/audit-log?phrase={phrase}&include=web&per_page=100"
                seen_paths = set()
                for page in range(1, 6):
                    seen_paths.add(audit_path)
                    result = client.get(audit_path)
                    if result["status"] != 200 or not isinstance(result.get("data"), list):
                        checks.append({"check": "github_audit_log", "status": result["status"] if result["status"] != 200 else "unexpected_audit_schema"})
                        break
                    for event in result["data"]:
                        if isinstance(event, dict):
                            observe_event(event, "github_audit_log", True)
                    next_path = result.get("next_path")
                    if not next_path or next_path in seen_paths or page == 5:
                        checks.append({"check": "github_audit_log", "status": "bounded_window", "pages": page,
                                       "has_more": bool(next_path)})
                        break
                    audit_path = next_path
                limitations.append("Organization audit access requires suitable permissions/plan; retained history and pages are limited.")
    else:
        checks.append({"check": "github_online_checks", "status": "offline" if offline else "unsupported_or_missing_github_identity"})
        if name and metadata.get("provider") == "github":
            repo_id = metadata.get("repository_id")

    # Provider-reported current visibility is separate from historical evidence.
    if metadata.get("available") and metadata.get("is_private") is False and not any(e["kind"] == "currently_public" for e in evidence):
        if metadata.get("visibility") == "public":
            add("currently_public", "provider_metadata", "confirmed", timestamp=observed_at)

    for path in evidence_paths or []:
        record = {"path": str(Path(path).absolute()), "records_read": 0, "matched_repository_records": 0}
        sources.append(record)
        try:
            record["sha256"] = _file_sha256(path)
            for event in _records(path):
                record["records_read"] += imported_record_count(event)
                record["matched_repository_records"] += observe_imported(event, "import:" + Path(path).name)
            record["status"] = "processed"
        except (OSError, ValueError, TypeError, EOFError) as exc:
            record["status"] = "error"
            record["error"] = type(exc).__name__
            limitations.append("An evidence file was unreadable or malformed; retained earlier records are partial.")

    if search_public_commits and not offline:
        # Uniform chronological sampling plus roots avoids only checking recent commits.
        ordered = (git(repo_path, "rev-list", "--reverse", "--all", "HEAD") or "").splitlines()
        ordered = list(dict.fromkeys(s for s in ordered if s in commits))
        count = max(0, min(int(max_search_commits), 30, len(ordered)))
        sample = [ordered[round(i * (len(ordered) - 1) / max(1, count - 1))] for i in range(count)]
        for sha in sample:
            result = client.get("/search/commits?q=" + parse.quote(sha + " is:public") + "&per_page=10", authenticated=False)
            data = result.get("data") or {}
            checks.append({"check": "public_commit_search", "sha": sha, "status": result["status"],
                           "incomplete_results": data.get("incomplete_results")})
            if result["status"] != 200:
                break
            for item in data.get("items", []):
                repository = item.get("repository") or {}
                if item.get("sha") == sha and repository.get("private") is False:
                    add("public_commit_match", "github_anonymous_commit_search", "code_match",
                        shas=[sha], repository_name=repository.get("full_name"),
                        repository_id=repository.get("id"), independently_fetched=True)
        limitations.append("Public commit search samples at most 30 hashes, is index-limited, and misses rewritten/squashed history.")
    elif search_public_commits:
        checks.append({"check": "public_commit_search", "status": "offline"})

    if native_identity and native_identity["provider"] == "gitlab" and not offline:
        # Injected provider clients are commonly offline fixtures; public and
        # archive requests need their own explicitly injected fixtures there.
        if provider_client is None or gitlab_public_client is not None:
            public_matches = collect_gitlab_public_matches(
                repo_path, snapshot, native_identity, commits, original_name=submitted_gitlab_name,
                client=gitlab_public_client)
            checks.extend(public_matches["checks"])
            limitations.extend(public_matches["limitations"])
            for finding in public_matches["evidence"]:
                detail = {k: v for k, v in finding.items() if k not in {"kind", "source", "strength"}}
                add(finding["kind"], finding["source"], finding["strength"], **detail)
        if provider_client is None or software_heritage_client is not None:
            archive_matches = collect_gitlab_archive_matches(
                native_identity, commits, original_name=submitted_gitlab_name,
                client=software_heritage_client)
            checks.extend(archive_matches["checks"])
            limitations.extend(archive_matches["limitations"])
            for finding in archive_matches["evidence"]:
                detail = {k: v for k, v in finding.items() if k not in {"kind", "source", "strength"}}
                add(finding["kind"], finding["source"], finding["strength"], **detail)

    references = []
    if public_reference_paths:
        manifest = _source_manifest(repo_path)
        index: Dict[str, List[Dict[str, Any]]] = {}
        for file in manifest["files"]:
            index.setdefault(file["normalized_sha256"], []).append(file)
        for path in public_reference_paths:
            entry: Dict[str, Any] = {"path": str(Path(path).absolute()), "public_source_verified_by_tool": False}
            references.append(entry)
            if not Path(path).is_dir():
                entry["status"] = "missing_reference"
                continue
            submitted_root, reference_root = Path(repo_path).resolve(), Path(path).resolve()
            if submitted_root == reference_root or submitted_root in reference_root.parents or reference_root in submitted_root.parents:
                entry["status"] = "overlapping_reference_not_compared"
                continue
            reference_snapshot = snapshot_repository(path, path)
            reference_shas = set(reference_snapshot.pop("commits"))
            entry["snapshot"] = reference_snapshot
            shared = sorted(commits & reference_shas)
            if shared:
                add("reference_commit_match", "local_reference:" + str(Path(path).absolute()), "code_match",
                    matched_commit_count=len(shared), shas=shared[:20])
            reference_manifest = _source_manifest(path)
            matches = []
            matched_paths = set()
            for file in reference_manifest["files"]:
                for candidate in index.get(file["normalized_sha256"], []):
                    matched_paths.add(candidate["path"])
                    if len(matches) < 50:
                        matches.append({"submitted_path": candidate["path"], "reference_path": file["path"],
                                        "sha256": candidate["sha256"], "normalized_sha256": candidate["normalized_sha256"]})
            entry.update({"status": "compared", "shared_commits": len(shared), "matched_source_files": len(matched_paths),
                          "submitted_source_files_examined": len(manifest["files"]),
                          "reference_source_files_examined": len(reference_manifest["files"]),
                          "scan_truncated": manifest["truncated"] or reference_manifest["truncated"],
                          "skipped_files": manifest["skipped"] + reference_manifest["skipped"]})
            if matches:
                add("reference_source_match", "local_reference:" + str(Path(path).absolute()), "code_match",
                    matched_source_file_count=len(matched_paths),
                    matched_source_percent=round(100 * len(matched_paths) / max(1, len(manifest["files"])), 2),
                    examples=matches)

    if not snapshot["history_readable"] or snapshot["shallow"] or snapshot["replace_refs_present"] or snapshot["grafts_present"]:
        add("history_coverage_gap", "local_git", "lead", shallow=snapshot["shallow"],
            replace_refs=snapshot["replace_refs_present"], grafts=snapshot["grafts_present"],
            history_readable=snapshot["history_readable"])

    confirmed = finding_flags["exposure"]
    code_match = finding_flags["code_match"]
    transition = finding_flags["transition"]
    status = "PUBLIC_EXPOSURE_EVIDENCE" if confirmed else "PUBLIC_CODE_MATCH" if code_match else "INCONCLUSIVE"
    audit = audit_availability(checks, evidence, requested=audit_log, offline=offline)
    # Score independent provenance observations on every run. Audit events can
    # confirm exposure, but must not inflate the separate heuristic estimate.
    provenance_evidence = [e for e in evidence if not (
        str(e.get("source", "")).endswith("_audit_log") or
        e.get("event_type") in {"repo.access", "repo.create"} or
        e.get("kind") == "public_to_private_transition" or
        (e.get("kind") == "historical_public_repository" and
         (e.get("action") is not None or e.get("previous_visibility") is not None or
          e.get("visibility") is not None)))]
    heuristic = estimate_public_origin(repo_path, snapshot, metadata,
                                       provenance_evidence, checks, git=git, audit=audit)
    return {
        "schema_version": 3, "generated_at": observed_at, "status": status,
        "recommendation": "REJECT" if confirmed else "MANUAL_REVIEW",
        "ever_public": True if confirmed else None,
        "public_to_private_transition": True if transition else None,
        "always_private_verified": False,
        "repository": {**snapshot, "github_name": name, "repository_id": repo_id,
                       "provider": native_identity["provider"] if native_identity else "github" if name else None,
                       "instance_url": native_identity["instance_url"] if native_identity else "https://github.com" if name else None,
                       "repository_name": native_identity["repository_name"] if native_identity else name},
        "provider_metadata": metadata, "evidence": evidence, "checks": checks,
        "public_exposure_estimate": heuristic,
        "evidence_sources": sources, "public_references": references, "limitations": limitations,
        "next_steps": [
            "Independently verify cited event IDs, repository IDs, timestamps and imported evidence sources.",
            "Obtain prior repository names/owners/providers and archived visibility/audit records from the vendor.",
            "Search GH Archive across the full repository lifetime and compare suspected public ancestors locally.",
            "Have a reviewer assess shared dependencies/templates and ownership before purchase.",
        ],
    }


def provenance_columns(result: Dict[str, Any]) -> Dict[str, Any]:
    estimate = result.get("public_exposure_estimate", {})
    reasons = {e["kind"] for e in result.get("evidence", [])}
    reasons.update("heuristic:" + s["signal"] for s in estimate.get("signals", [])
                   if s.get("contribution_points", 0) > 0)
    return {
        "provenance_provider": result.get("repository", {}).get("provider"),
        "provenance_instance_url": result.get("repository", {}).get("instance_url"),
        "provenance_status": result.get("status", "INCONCLUSIVE"),
        "provenance_recommendation": result.get("recommendation", "MANUAL_REVIEW"),
        "public_exposure_estimate_status": result.get("public_exposure_estimate", {}).get("status"),
        "public_exposure_estimate_percent": result.get("public_exposure_estimate", {}).get("likelihood_percent"),
        "public_exposure_estimate_reason": result.get("public_exposure_estimate", {}).get("audit", {}).get("reason"),
        "ever_public": True if result.get("ever_public") is True else "UNKNOWN",
        "public_to_private_transition": (True if result.get("public_to_private_transition") is True
                                         else "UNKNOWN"),
        "provenance_evidence_count": len(result.get("evidence", [])),
        "provenance_reasons": " | ".join(sorted(reasons)) or "Historical privacy unverified",
    }


def save_provenance(result: Dict[str, Any], output_dir: str) -> Dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report = output / "provenance.json"
    tmp = report.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, report)
    paths = {"report": str(report)}
    pdf = output / "provenance.pdf"
    pdf_tmp = output / "provenance.pdf.tmp"
    try:
        # The client PDF is an additional artifact. A rendering/dependency
        # failure must not discard the JSON or stop the analysis pipeline.
        from provenance_pdf import build_client_pdf
        build_client_pdf(result, pdf_tmp)
        os.replace(pdf_tmp, pdf)
        paths["pdf"] = str(pdf)
    except Exception as exc:
        for stale in (pdf_tmp, pdf):
            try:
                stale.unlink(missing_ok=True)
            except OSError:
                pass
        hint = " Install requirements with: python -m pip install -r requirements.txt." if isinstance(exc, ModuleNotFoundError) else ""
        warnings.warn("Client PDF was not generated (%s); provenance.json was saved.%s" %
                      (type(exc).__name__, hint), RuntimeWarning)
    if result["repository"].get("provider") not in {None, "github"}:
        return paths
    names = [result["repository"]["github_name"]] if result["repository"].get("github_name") else []
    query = output / "gharchive_query.sql"
    current_year = dt.datetime.now(dt.timezone.utc).year
    query.write_text(build_archive_query(names, result["repository"].get("repository_id"), current_year), encoding="utf-8")
    years = output / "gharchive_queries"
    years.mkdir(exist_ok=True)
    for year in range(2011, current_year + 1):
        (years / f"{year}.sql").write_text(build_archive_query(names, result["repository"].get("repository_id"), year), encoding="utf-8")
    paths.update(archive_query=str(query), archive_queries=str(years))
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Local submitted repository/directory; never executes its code")
    parser.add_argument("--repository-url", help="Original provider URL if origin was removed")
    parser.add_argument("--github-token", default=None)
    parser.add_argument("--gitlab-token", default=None)
    parser.add_argument("--bitbucket-token", default=None)
    parser.add_argument("--provider", choices=["gitlab", "bitbucket_cloud", "bitbucket_server"])
    parser.add_argument("--instance-url", help="Explicit trusted HTTPS instance/context URL for self-hosted deployments")
    parser.add_argument("--atlassian-org-id", default=None)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--evidence", action="append", default=[], help="Raw GitHub/GH Archive JSON/JSONL(.gz); repeatable")
    parser.add_argument("--public-reference", action="append", default=[], help="Local known-public source directory; repeatable")
    parser.add_argument("--audit-log", "--github-audit-log", dest="audit_log", action="store_true", help="Read organization audit API; personal GitHub accounts use provenance signals")
    parser.add_argument("--github-security-log-profile", help="Deprecated and ignored; personal browser Security-log collection is disabled")
    parser.add_argument("--search-public-commits", action="store_true", help="Send up to 8 commit hashes to anonymous GitHub search")
    parser.add_argument("--output-dir", default="./outputs/provenance")
    args = parser.parse_args()
    if not Path(args.repo).is_dir():
        parser.error("--repo must be an existing local directory")
    result = analyze_provenance(args.repo, args.repository_url or args.repo,
                                github_token=args.github_token or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"),
                                offline=args.offline, evidence_paths=args.evidence,
                                public_reference_paths=args.public_reference, audit_log=args.audit_log,
                                personal_security_profile=args.github_security_log_profile,
                                gitlab_token=args.gitlab_token or os.getenv("GITLAB_TOKEN") or os.getenv("GL_TOKEN"),
                                bitbucket_token=args.bitbucket_token or os.getenv("BITBUCKET_TOKEN") or os.getenv("BB_TOKEN"),
                                provider=args.provider, provider_instance_url=args.instance_url,
                                atlassian_org_id=args.atlassian_org_id or os.getenv("ATLASSIAN_ORG_ID"),
                                atlassian_admin_token=os.getenv("ATLASSIAN_ADMIN_TOKEN"),
                                search_public_commits=args.search_public_commits)
    paths = save_provenance(result, args.output_dir)
    print(f"{result['status']}: {result['recommendation']}")
    estimate = result["public_exposure_estimate"]
    if estimate["status"] == "ESTIMATE":
        score = estimate["likelihood_percent"]
        print(f"Public exposure estimate: {str(score) + '%' if score is not None else 'insufficient observations'} (heuristic; not confirmed)")
    print(f"Evidence report: {paths['report']}")
    if paths.get("pdf"):
        print(f"Client PDF: {paths['pdf']}")
    print("Always-private status cannot be established automatically.")
    raise SystemExit(1 if result["recommendation"] == "REJECT" else 3)


if __name__ == "__main__":
    main()
