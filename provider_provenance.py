"""GitLab and Bitbucket provenance adapters, scoped to a provider instance.

Native audit schemas are normalized conservatively. A changed privacy setting
with no explicit public value is a lead, never proof of a public/private switch.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from urllib import error, parse, request


PROVIDERS = {"gitlab", "bitbucket_cloud", "bitbucket_server"}


def instance_url(url: str) -> Optional[str]:
    try:
        parts = parse.urlsplit(url)
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password or
                parts.query or parts.fragment or ".." in parse.unquote(parts.path).split("/")):
            return None
        return parse.urlunsplit(("https", parts.netloc.lower(), parts.path.rstrip("/"), "", ""))
    except ValueError:
        return None


def identify_repository(url: str, provider: Optional[str] = None,
                        base_url: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Self-hosted deployments require an explicit HTTPS instance for credentials."""
    try:
        scp = re.match(r"^[^@/]+@([^/:]+):(.+)$", url)
        parts = parse.urlsplit("ssh://git@" + scp.group(1) + "/" + scp.group(2) if scp else url)
        host = (parts.hostname or "").lower()
        path = parts.path.strip("/")
        if not host or parts.scheme not in {"https", "http", "ssh"}:
            return None
        if provider is None:
            if host == "gitlab.com" or host.startswith("gitlab.") or ".gitlab." in host:
                provider = "gitlab"
            elif host == "bitbucket.org":
                provider = "bitbucket_cloud"
            elif "bitbucket" in host or "/scm/" in parts.path or re.match(r"projects/[^/]+/repos/", path):
                provider = "bitbucket_server"
        if provider not in PROVIDERS:
            return None
        if host == "github.com" or (host == "gitlab.com" and provider != "gitlab") or (host == "bitbucket.org" and provider != "bitbucket_cloud"):
            return None
        if provider == "bitbucket_cloud" and host != "bitbucket.org":
            return None
        base = instance_url(base_url) if base_url else "https://" + host
        if not base or parse.urlsplit(base).hostname != host:
            return None
        prefix = parse.urlsplit(base).path.strip("/")
        if prefix:
            if not path.startswith(prefix + "/"):
                return None
            path = path[len(prefix) + 1:]
        path = path.split("/-/", 1)[0].rstrip("/")
        if provider == "bitbucket_server":
            path = re.sub(r"^scm/", "", path)
            match = re.match(r"projects/([^/]+)/repos/([^/]+)(?:/.*)?$", path)
            if match:
                path = "/".join(match.groups())
        if path.endswith(".git"):
            path = path[:-4]
        segments = path.split("/")
        if (len(segments) < 2 or (provider != "gitlab" and len(segments) != 2) or
                any(s in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.~{}-]+", s) for s in segments)):
            return None
        return {"provider": provider, "instance_url": base, "repository_name": path,
                "repository_id": None, "credentials_allowed": bool(base_url) or host in {"gitlab.com", "bitbucket.org"}}
    except ValueError:
        return None


class ScopedClient:
    """Read-only JSON requests; credentials and next links stay inside one base URL."""
    def __init__(self, base_url: str, token: Optional[str], token_header: str = "Authorization",
                 timeout: int = 20):
        self.base = instance_url(base_url)
        if not self.base:
            raise ValueError("Provider instance must be a credential-free HTTPS URL")
        self.token = token
        self.token_header = token_header
        self.timeout = timeout

    def scoped_path(self, url: str) -> Optional[str]:
        absolute = parse.urljoin(self.base + "/", url)
        try:
            parts = parse.urlsplit(absolute)
            base = parse.urlsplit(self.base)
            if (parts.scheme != "https" or parts.netloc.lower() != base.netloc.lower() or
                    parts.username or parts.password or ".." in parse.unquote(parts.path).split("/")):
                return None
            prefix = base.path.rstrip("/")
            if prefix and not parts.path.startswith(prefix + "/"):
                return None
            return parts.path[len(prefix):] + ("?" + parts.query if parts.query else "")
        except ValueError:
            return None

    def get(self, path: str, authenticated: bool = True) -> Dict[str, Any]:
        # Application paths are relative to the instance's context path.
        url = path if path.startswith("https://") else self.base + "/" + path.lstrip("/")
        scoped = self.scoped_path(url)
        if scoped is None:
            return {"status": "unsafe_api_url", "data": None}
        headers = {"Accept": "application/json", "User-Agent": "repo-provenance-analyzer"}
        if authenticated and self.token:
            headers[self.token_header] = self.token if self.token_header == "PRIVATE-TOKEN" else "Bearer " + self.token

        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        try:
            with request.build_opener(NoRedirect()).open(request.Request(url, headers=headers), timeout=self.timeout) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    return {"status": "response_too_large", "data": None}
                link = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get("Link", ""))
                next_url = link.group(1) if link else None
                # Return a full URL so self-hosted context paths cannot be lost.
                if next_url and self.scoped_path(next_url) is None:
                    next_url = None
                return {"status": response.status, "data": json.loads(raw), "next_url": next_url, "request_url": url}
        except error.HTTPError as exc:
            return {"status": exc.code, "data": None}
        except (OSError, ValueError):
            return {"status": "network_or_json_error", "data": None}


def visibility(value: Any, field: str = "visibility", allow_gitlab_levels: bool = False) -> Optional[str]:
    text = str(value).strip().lower()
    if field in {"public", "is_private"}:
        if text not in {"true", "false"}:
            return None
        public = text == ("false" if field == "is_private" else "true")
        return "public" if public else "private"
    values = {"public": "public", "private": "private", "internal": "internal"}
    if allow_gitlab_levels:
        values.update({"20": "public", "10": "internal", "0": "private"})
    return values.get(text)


def _visibility_changes(changes: Any) -> tuple:
    pairs = []
    for change in changes if isinstance(changes, list) else []:
        if not isinstance(change, dict):
            continue
        field = None
        for label in ("key", "field", "name", "i18nKey"):
            key = str(change.get(label) or "").lower()
            compact = re.sub(r"[ _.-]", "", key)
            if compact in {"isprivate", "private"}:
                field = "is_private"
            elif compact in {"public", "publicaccess", "repositorypublic", "repositorypublicaccess"} or ("repository" in key and key.endswith((".public", ".public.access"))):
                field = "public"
            elif "visibility" in compact or "privacy" in compact:
                field = "visibility"
            if field:
                break
        if field:
            old = visibility(change.get("from", change.get("oldValue")), field)
            new = visibility(change.get("to", change.get("newValue")), field)
            pairs.append((old, new))
    # Conflicting visibility fields are ambiguous and must not imply conversion.
    return pairs[0] if pairs and len(set(pairs)) == 1 else (None, None)


def normalize_audit(event: Dict[str, Any], provider: str, source_instance: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Parse native audit records without interpreting a generic privacy edit as exposure."""
    if not isinstance(event, dict):
        return None
    normalized: Dict[str, Any] = {"provider": provider, "instance_url": instance_url(source_instance or ""),
                                  "event_id": event.get("id"), "repository_id": None, "repository_name": None,
                                  "previous_visibility": None, "visibility": None,
                                  "raw_event_sha256": hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()}
    if provider == "gitlab":
        details = event.get("details") or {}
        if not isinstance(details, dict) or event.get("entity_type") != "Project":
            return None
        action = event.get("event_type") or details.get("event_name") or ""
        change = str(details.get("change") or "").lower()
        if action != "project_visibility_level_updated" and change not in {"visibility", "visibility level", "visibility_level"}:
            return None
        normalized.update(repository_id=event.get("entity_id"),
                          repository_name=details.get("entity_path") or details.get("target_details"),
                          timestamp=event.get("created_at"), action=action or change,
                          previous_visibility=visibility(details.get("from"), allow_gitlab_levels=True),
                          visibility=visibility(details.get("to"), allow_gitlab_levels=True))
        # A project-scoped event must not smuggle a different target project ID.
        if details.get("target_type") == "Project" and details.get("target_id") is not None and str(details["target_id"]) != str(event.get("entity_id")):
            return None
    elif provider == "bitbucket_server":
        affected = event.get("affectedObjects") or []
        repos = [o for o in affected if isinstance(o, dict) and str(o.get("type") or o.get("typeName") or "").lower() == "repository"]
        if len(repos) != 1:
            return None
        event_type = event.get("type") or event.get("auditType") or {}
        if not isinstance(event_type, dict):
            return None
        action = str(event_type.get("actionI18nKey") or event_type.get("action") or "")
        old, new = _visibility_changes(event.get("changedValues"))
        if old is None and new is None and not any(word in action.lower() for word in ("privacy", "public", "visibility")):
            return None
        repo = repos[0]
        uri = repo.get("uri") or ""
        parsed = identify_repository(uri, provider=provider, base_url=source_instance) if uri else None
        normalized.update(repository_id=repo.get("id"), repository_name=parsed["repository_name"] if parsed else repo.get("name"),
                          timestamp=event.get("timestamp"), action=action,
                          previous_visibility=old, visibility=new)
    elif provider == "bitbucket_cloud":
        attrs = event.get("attributes") or {}
        if not isinstance(attrs, dict):
            return None
        context = attrs.get("context") or []
        repos = [o for o in context if isinstance(o, dict) and str(o.get("type") or "").lower() in {"repository", "repositories", "bitbucket.repository"}]
        if len(repos) != 1:
            return None
        repo = repos[0]
        action = str(attrs.get("action") or "")
        message = event.get("message") or {}
        message = message.get("content", "") if isinstance(message, dict) else ""
        repo_attrs = repo.get("attributes") or {}
        if not isinstance(repo_attrs, dict):
            return None
        old, new = _visibility_changes(attrs.get("changedValues") or attrs.get("changes") or repo_attrs.get("changes"))
        if old is None and new is None and not any(word in (action + " " + message).lower() for word in ("privacy", "visibility", "is_private")):
            return None
        links = repo.get("links") or {}
        repo_url = links.get("alt") or links.get("self") or ""
        parsed = identify_repository(repo_url, provider=provider) if repo_url else None
        normalized.update(repository_id=repo.get("id"), repository_name=parsed["repository_name"] if parsed else repo_attrs.get("full_name"),
                          timestamp=attrs.get("time"), action=action or message,
                          previous_visibility=old, visibility=new)
        # UUIDs identify Bitbucket Cloud repositories globally. Still require an
        # explicit instance on imports; Atlassian logs can contain other products.
    else:
        return None
    return normalized


def match_audit(event: Dict[str, Any], identity: Dict[str, Any]) -> Optional[str]:
    if event.get("provider") != identity.get("provider"):
        return None
    event_instance = event.get("instance_url")
    target_instance = identity.get("instance_url")
    if event_instance and event_instance != target_instance:
        return None
    def identifier(value):
        return str(value).strip("{}").lower() if value is not None else None
    current, old = identifier(identity.get("repository_id")), identifier(event.get("repository_id"))
    if current is not None and old is not None:
        if current != old:
            return None
        return "repository_id_and_instance" if event_instance == target_instance and event_instance else "unscoped_repository_id"
    names = (identity.get("repository_name"), event.get("repository_name"))
    return "name_only" if all(names) and names[0].lower() == names[1].lower() else None


def collect_provider(identity: Dict[str, Any], *, token: Optional[str], audit_log: bool,
                     offline: bool, metadata: Optional[Dict[str, Any]] = None,
                     atlassian_org_id: Optional[str] = None, atlassian_token: Optional[str] = None,
                     client: Optional[Any] = None, admin_client: Optional[Any] = None) -> Dict[str, Any]:
    """Collect current identity and bounded native audits. Never reports a clean history."""
    identity = dict(identity)
    provider, base, name = identity["provider"], identity["instance_url"], identity["repository_name"]
    result = {"identity": identity, "metadata": dict(metadata or {}), "checks": [], "events": [], "limitations": [], "public_ancestors": []}
    checks = result["checks"]
    if offline:
        existing = result["metadata"]
        if existing.get("provider") == provider and existing.get("instance_url") == base:
            identity["repository_id"] = existing.get("repository_id")
        checks.append({"check": provider + "_online_checks", "status": "offline"})
        return result
    if token and not identity["credentials_allowed"]:
        token = None
        checks.append({"check": provider + "_credentials", "status": "explicit_instance_url_required_for_self_hosted_credentials"})
    api_base = "https://api.bitbucket.org/2.0" if provider == "bitbucket_cloud" else base
    client = client or ScopedClient(api_base, token, "PRIVATE-TOKEN" if provider == "gitlab" else "Authorization")
    if provider == "gitlab":
        path = "/api/v4/projects/" + parse.quote(name, safe="")
    elif provider == "bitbucket_cloud":
        path = "/repositories/" + "/".join(parse.quote(s, safe="") for s in name.split("/"))
    else:
        project, slug = name.split("/")
        path = f"/rest/api/1.0/projects/{parse.quote(project, safe='')}/repos/{parse.quote(slug, safe='')}"
    raw = {}
    for authenticated in (True, False):
        fetched = client.get(path, authenticated=authenticated)
        checks.append({"check": provider + ("_repository_metadata" if authenticated else "_anonymous_visibility"), "status": fetched["status"]})
        data = fetched.get("data")
        if fetched["status"] != 200 or not isinstance(data, dict):
            continue
        record_id = data.get("uuid") if provider == "bitbucket_cloud" else data.get("id")
        if record_id is None:
            checks.append({"check": provider + "_repository_identity", "status": "repository_id_missing"})
            continue
        if identity["repository_id"] is not None and str(record_id).lower() != str(identity["repository_id"]).lower():
            checks.append({"check": provider + "_repository_identity", "status": "conflicting_anonymous_repository_id"})
            continue
        identity["repository_id"] = record_id
        raw = data
        # Anonymous access by itself is insufficient (e.g. a cached response).
        # Explicit provider visibility is required for a public observation.
        if provider == "gitlab":
            vis = visibility(data.get("visibility"))
            canonical = data.get("path_with_namespace") or name
            parent = data.get("forked_from_project") or {}
            parent_public = parent.get("visibility") == "public"
        elif provider == "bitbucket_cloud":
            vis = visibility(data.get("is_private"), "is_private")
            canonical = data.get("full_name") or name
            parent = data.get("parent") or {}
            parent_public = parent.get("is_private") is False
        else:
            vis = visibility(data.get("public"), "public")
            canonical = (data.get("project") or {}).get("key", name.split("/")[0]) + "/" + data.get("slug", name.split("/")[1])
            parent = data.get("origin") or {}
            parent_public = parent.get("public") is True
        identity["repository_name"] = canonical
        result["metadata"] = {
            **result["metadata"], "available": True, "provider": provider, "instance_url": base,
            "repository_id": record_id, "full_name": canonical, "visibility": vis,
            "is_private": vis == "private" if vis is not None else None,
            "is_fork": bool(parent), "description": data.get("description"),
            "default_branch": data.get("default_branch") or (data.get("mainbranch") or {}).get("name"),
            "created_at": data.get("created_at") or data.get("created_on"),
            "pushed_at": data.get("last_activity_at") or data.get("updated_on"),
            "stars": data.get("star_count"), "forks": data.get("forks_count"),
            "language": data.get("language"), "topics": data.get("topics", []),
            "license": (data.get("license") or {}).get("spdx_id"),
            "size_kb": data.get("size", 0) // 1024 if isinstance(data.get("size"), int) else None,
            "owner": canonical.rsplit("/", 1)[0], "open_issues": data.get("open_issues_count"),
        }
        if parent_public:
            result["public_ancestors"].append({"repository_id": parent.get("uuid") or parent.get("id"),
                                               "repository_name": parent.get("full_name") or parent.get("path_with_namespace") or parent.get("slug")})
        if vis == "public":
            # Preserve positive visibility if a later API observation disagrees.
            result["public_observed"] = True
    if not raw:
        result["limitations"].append(provider + " identity unavailable; access failures never establish privacy.")
    if not audit_log:
        checks.append({"check": provider + "_audit_log", "status": "not_requested"})
        return result
    if identity["repository_id"] is None:
        checks.append({"check": provider + "_audit_log", "status": "verified_repository_identity_required"})
        return result
    if provider == "gitlab":
        audit_path = f"/api/v4/projects/{identity['repository_id']}/audit_events?per_page=100&pagination=keyset&created_after=1970-01-01T00%3A00%3A00Z"
        rows_key = None
        result["limitations"].append("GitLab project audits require supported tier/permissions; Developer access may show only the caller's actions.")
    elif provider == "bitbucket_cloud":
        if not atlassian_org_id or not atlassian_token:
            checks.append({"check": provider + "_audit_log", "status": "atlassian_org_id_and_admin_token_required"})
            return result
        if not re.fullmatch(r"[A-Za-z0-9-]+", atlassian_org_id):
            checks.append({"check": provider + "_audit_log", "status": "invalid_atlassian_org_id"})
            return result
        client = admin_client or ScopedClient("https://api.atlassian.com/admin", atlassian_token)
        audit_path = f"/v1/orgs/{atlassian_org_id}/events?limit=100"
        rows_key = "data"
        result["limitations"].append("Bitbucket Cloud audits use Atlassian organization admin access and plan-dependent event availability; repository tokens alone do not grant it.")
    else:
        audit_path = "/rest/auditing/1.0/events?limit=100&affectedObject=" + parse.quote("REPOSITORY," + str(identity["repository_id"]), safe="")
        rows_key = "entities"
        result["limitations"].append("Bitbucket Data Center audits depend on version, admin rights, enabled coverage and retained records.")
    if provider != "bitbucket_cloud" and not token:
        checks.append({"check": provider + "_audit_log", "status": "token_required"})
        return result
    pages, records, seen = 0, 0, set()
    while audit_path and pages < 5:
        if audit_path in seen:
            checks.append({"check": provider + "_audit_pagination", "status": "repeated_next_link"})
            break
        seen.add(audit_path)
        fetched = client.get(audit_path)
        pages += 1
        body = fetched.get("data")
        rows = body.get(rows_key) if isinstance(body, dict) and rows_key else body
        if fetched["status"] != 200 or not isinstance(rows, list):
            checks.append({"check": provider + "_audit_log", "status": fetched["status"] if fetched["status"] != 200 else "unexpected_audit_schema", "pages": pages})
            break
        for record in rows:
            records += 1
            try:
                normalized = normalize_audit(record, provider, base)
            except (TypeError, ValueError, AttributeError):
                checks.append({"check": provider + "_audit_record", "status": "malformed_record"})
                continue
            if normalized:
                result["events"].append(normalized)
        next_url = fetched.get("next_url")
        if isinstance(body, dict):
            if provider == "bitbucket_cloud":
                next_url = (body.get("links") or {}).get("next")
                if not next_url and (body.get("meta") or {}).get("next"):
                    next_url = f"/v1/orgs/{atlassian_org_id}/events?limit=100&cursor=" + parse.quote(str(body["meta"]["next"]), safe="")
            else:
                next_url = (body.get("pagingInfo") or {}).get("nextPageLink")
        # The client checks scope again before sending any credentials.
        if next_url:
            current_url = fetched.get("request_url") or getattr(client, "base", base).rstrip("/") + "/" + audit_path.lstrip("/")
            next_url = parse.urljoin(current_url, next_url)
        audit_path = next_url
        checks.append({"check": provider + "_audit_log", "status": "bounded_window", "pages": pages,
                       "records_read": records, "recognized_visibility_events": len(result["events"]),
                       "has_more": bool(audit_path)})
    result["limitations"].append("Native audit retrieval is capped at five pages; missing, expired or filtered events cannot establish lifetime privacy.")
    return result
