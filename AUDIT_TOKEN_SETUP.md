# Tokens and permissions for repository audit logs

Use this guide when checking whether a submitted repository was previously public.
It covers the providers supported by this project: GitHub.com, GitLab.com or
self-managed GitLab, Bitbucket Cloud, and Bitbucket Data Center. The relevant
"access log" here is the provider's **audit event log** for repository settings,
especially visibility changes. Git commits and clone history do not contain that
setting history. A token only grants access to events that the provider recorded
and still retains.

**The credential must come from the organization, project, or instance that owns
the vendor repository.** A token created in your own unrelated account cannot
read a vendor's private audit log. Ask the vendor's authorized owner/admin to run
the check with you, or to provide a verifiable audit export. Do not accept a
read-only repository token as proof that audit events are available.

## Quick decision table

| Provider | Credential for private repository data | Credential and role for audit events | Tool variables |
| --- | --- | --- | --- |
| GitHub personal account | Fine-grained PAT with selected repository and **Contents: Read** for private repository analysis. | No automatic personal Security-log read. The tool uses public and local provenance signals and labels the result as an estimate. | `GITHUB_TOKEN` |
| GitHub organization on Enterprise Cloud | Fine-grained PAT: selected repository, **Contents: Read**; Metadata read is automatic. For full analysis, add the read permissions needed by PR, issue, and Actions endpoints. | Organization **owner** with a fine-grained PAT carrying **Organization permissions → Administration: Read**, or a classic PAT with `read:audit_log`. The audit REST API requires Enterprise Cloud. | `GITHUB_TOKEN` |
| GitLab project, Premium/Ultimate | Legacy personal, group, or project access token with `read_api` for API data; add `read_repository` for HTTPS cloning. | Project **Maintainer or higher** to see all users' project audit events; a Developer sees only their own actions. A token must have `read_api`, and its identity must hold the role. | `GITLAB_TOKEN` |
| Bitbucket Cloud | Repository access token with **Repositories: Read**; add **Pull requests: Read** and **Pipelines: Read** for those full-analysis stages. A user API token with equivalent Bitbucket read scopes is another option. | A **separate Atlassian organization admin API key** with `read:events:admin`, plus the Atlassian organization ID. A Bitbucket repository/workspace token cannot grant this access. | `BITBUCKET_TOKEN`, `ATLASSIAN_ADMIN_TOKEN`, `ATLASSIAN_ORG_ID` |
| Bitbucket Data Center | A **user HTTP access token** with repository read access for API reads. | The token's user must have administrator, system administrator, or applicable delegated administrator access to the audit events on that deployment. Repository/project token permissions alone are not an audit entitlement. | `BITBUCKET_TOKEN` |

The same environment variable supplies repository and audit requests within a
provider, except for Bitbucket Cloud's separate Atlassian admin key. Giving a
token a scope does not increase the user's underlying organization/project role.
These are the minimum permissions for the stated reads; optional stages of the
full analyzer may need additional read scopes.

For a **GitHub personal account**, there is no documented PAT endpoint for the
personal Security log. The analyzer does not collect it through a browser.
`--provenance-audit-log` records that an organization audit API is not applicable,
then uses provenance signals and a labeled heuristic estimate. A repository PAT
cannot read another user's personal Security log.

## GitHub.com

1. Confirm that the repository is owned by a **GitHub organization on Enterprise
   Cloud** and that the credential holder is an **organization owner**. The
   organization audit REST endpoint is `/orgs/ORG/audit-log`; a personal account
   has no equivalent organization log. [Audit API and token permissions][gh-api]
   and [availability and retention][gh-retention].
2. In GitHub, open **Profile → Settings → Developer settings → Personal access
   tokens → Fine-grained tokens → Generate new token**. Select the vendor
   organization as **Resource owner**, select the submitted repository, grant
   repository **Contents: Read**, and grant organization **Administration: Read**.
   Add **Pull requests: Read**, **Issues: Read**, and **Actions: Read** if the
   corresponding full-analysis API calls are needed. If the organization requires
   token approval, have its owner approve the request. [PAT creation][gh-pat].
3. If a classic PAT is required, use **Personal access tokens → Tokens (classic)**
   and grant `read:audit_log` for the audit endpoint. Add `repo` if the same token
   must access private repository data; `repo` is broader than read-only access.
   An organization can restrict classic PATs. [Audit API][gh-api].
4. Put the token in `GITHUB_TOKEN` in the local `.env` used by the main analyzer.
   `--provenance-audit-log` asks for the organization audit endpoint.

The tool reads at most five pages of audit results. GitHub's organization web
audit log retains the last 180 days of activity; provider retention and API
coverage limit historical conclusions. If the vendor is not an organization
owner, ask that owner to export the records. A missing event never proves that
the repository was always private. [Audit retention][gh-retention].

## GitLab.com and self-managed GitLab

1. Check that the vendor's project is on **Premium or Ultimate**. Have a
   **Maintainer or higher** create the credential to retrieve all users' project
   audit events. Developer access only covers the Developer's own actions.
   [GitLab project audit API][gl-audit] and [role rules][gl-events].
2. For a user token, open **Avatar → Edit profile → Access → Personal access
   tokens → Generate token → Legacy token**. Select `read_api` for metadata,
   merge requests, and audit API reads. Also select `read_repository` if the tool
   must clone the private repository over HTTPS. Give the token an expiry and
   store its value once. [PAT creation][gl-pat] and [scope definitions][gl-scopes].
3. A **group access token** or **project access token** with the same scopes can
   be limited to that group/project, but its bot identity must have the required
   project role. For a project token, select the Maintainer role when creating
   it and verify audit access on the actual GitLab deployment. Group tokens
   inherit only their group's reach. [Token reach][gl-scopes].
4. Put the token in `GITLAB_TOKEN`. For self-managed GitLab, also pass
   `--provenance-provider gitlab --provenance-instance-url
   "https://gitlab.example.com"` (include any context path). The instance URL
   must be an HTTPS host you trust before the provenance client sends a token.

GitLab's audit UI is **Project → Secure → Audit events**. Project audit queries
with both `created_after` and `created_before` dates are limited to 30-day
windows. The current tool requests a bounded first portion of events, so for an
older submission use vendor-side exports or repeated date-window API requests
and import the resulting native JSON with `--provenance-evidence`. The tool does
not establish complete lifetime coverage. [GitLab audit events][gl-events].

## Bitbucket Cloud

There are **two separate credentials** for this project's Cloud workflow.

1. For repository data, the vendor's repository admin can open **Repository →
   Settings → Security → Access tokens → Create access token**. Choose
   **Repositories: Read**. For full PR and pipeline analysis, also choose **Pull
   requests: Read** and **Pipelines: Read**. Set `BITBUCKET_TOKEN` in `.env`.
   Project/workspace access tokens cover more repositories and require Bitbucket
   Cloud Premium. [Create repository token][bb-create], [permission meanings][bb-perms],
   and [token reach][bb-types].
2. If a vendor uses a **user API token** instead, create it through **Atlassian
   account → Security → Create and manage API tokens → Create API token with
   scopes → Bitbucket**. Select `read:repository:bitbucket`, and add
   `read:pullrequest:bitbucket`, `read:pipeline:bitbucket`, and
   `read:issue:bitbucket` for the corresponding analysis features. The user must
   have repository access. The current tool sends the token as a Bearer token to
   Bitbucket's REST API; Atlassian also documents `x-token-auth` for HTTPS Git
   cloning. [Create user API token][bb-user-create], [scope meanings][bb-user-scopes],
   and [authentication examples][bb-user-auth].
3. For the **organization audit API**, an **Atlassian organization admin** opens
   **admin.atlassian.com → select organization → Organization settings → API
   keys → API keys with scopes → Create API key**. Select the single scope
   `read:events:admin`, copy the key once, and set `ATLASSIAN_ADMIN_TOKEN`.
   [Admin key creation][at-admin] and [event API scope][at-events].
4. On the chosen organization page, take the ID after `/o/` in the
   `admin.atlassian.com/o/ORG_ID/...` URL and set `ATLASSIAN_ORG_ID=ORG_ID`.
   This is different from a Bitbucket workspace slug or Atlassian site Cloud ID.
   [Organization URL example][at-org-id].

The tool calls the [Atlassian organization events API][at-events] with the admin
key and matches events against the Bitbucket repository UUID. Organization
event availability varies with Atlassian plans/configuration and event types.
Bitbucket's **Workspace settings → Security → Audit log** is a separate UI log;
the tool does not query that workspace log. A privacy event without explicit
old/new visibility values is kept as an unresolved lead. [Bitbucket Cloud audit
logs][bb-cloud-logs].

## Bitbucket Data Center

1. On the vendor's Data Center instance, an authorized administrator can open
   **Profile picture → Manage account → HTTP access tokens → Create token**.
   Create a **user** token with repository read access and an expiry. Put it in
   `BITBUCKET_TOKEN`. Repository/project HTTP tokens can read code, but their
   permission level does not make them a user with audit administrator rights.
   [HTTP token creation and levels][dc-token].
2. Ensure the token's user is permitted to view the relevant audit events.
   Administrators, system administrators, and delegated administrators can see
   project/repository audit logs according to the instance configuration.
   Admin UI: **Administration → Audit log** or **Project/Repository settings →
   Security → Audit log**. [Audit roles and UI][dc-audit].
3. Pass `--provenance-provider bitbucket_server` and a trusted HTTPS base such
   as `--provenance-instance-url "https://code.example.com/bitbucket"`. The
   collector calls `/rest/auditing/1.0/events` under that base. Confirm the
   instance exposes this endpoint and records repository visibility events.
   [Audit REST retrieval][dc-rest].

The Data Center audit database has configurable retention and coverage; disabled
or expired events cannot be recovered by raising token permissions. The tool
reads up to five pages. Older audit files may be kept by the instance's logging
or SIEM setup. [Retention and coverage][dc-audit].

## Run and check access

Copy `.env.example` to `.env`, fill only the needed values, and keep `.env`
private. The main analyzer loads `.env`; the standalone `provenance.py` reads
tokens from the **process environment** instead. Avoid putting tokens directly
on command lines because commands can be saved in shell history.

```powershell
python Repo_analysis_tool.py -i "D:\VendorRepos\payment-api" --mode full --provenance-audit-log
```

For a self-hosted instance, add its provider and HTTPS instance URL as shown
above. A local clone should retain its `.git` history and original `origin` URL;
otherwise supply `--repository-url` to the standalone provenance command. If
the vendor gives an audit export, pass `--provenance-evidence PATH` to the main
analyzer or `--evidence PATH` to `provenance.py`. See [PROVENANCE_NATIVE.md](./PROVENANCE_NATIVE.md)
for the required export envelope and identity checks.

Inspect the generated `provenance.json` **checks** array after the run. A
provider's `*_audit_log` check with HTTP `401` usually means an invalid/expired
credential; `403` often means insufficient role, scope, plan, or organization
policy; `404` can indicate wrong organization/instance, hidden resource, or an
unsupported endpoint. `token_required`, `verified_repository_identity_required`,
and `atlassian_org_id_and_admin_token_required` tell you which prerequisite is
missing. A `bounded_window` result means that pages were read, **not** that the
repository was always private. Ask the vendor admin for provider-generated
records and verify repository IDs, timestamps, and coverage independently.

[gh-api]: https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization
[gh-pat]: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
[gh-retention]: https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization
[gl-audit]: https://docs.gitlab.com/api/audit_events/#project-audit-events
[gl-events]: https://docs.gitlab.com/user/compliance/audit_events/
[gl-pat]: https://docs.gitlab.com/user/profile/personal_access_tokens/
[gl-scopes]: https://docs.gitlab.com/security/tokens/access_token_scopes/
[bb-create]: https://support.atlassian.com/bitbucket-cloud/docs/create-a-repository-access-token/
[bb-perms]: https://support.atlassian.com/bitbucket-cloud/docs/repository-access-token-permissions/
[bb-types]: https://support.atlassian.com/bitbucket-cloud/docs/access-tokens/
[bb-user-create]: https://support.atlassian.com/bitbucket-cloud/docs/create-an-api-token/
[bb-user-scopes]: https://support.atlassian.com/bitbucket-cloud/docs/api-token-permissions/
[bb-user-auth]: https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/
[at-admin]: https://support.atlassian.com/organization-administration/docs/manage-an-organization-with-the-admin-apis/
[at-events]: https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events/
[at-org-id]: https://support.atlassian.com/atlassian-cloud/kb/get-an-atlassian-cloud-users-account-id/
[bb-cloud-logs]: https://support.atlassian.com/bitbucket-cloud/kb/bitbucket-cloud-audit-log-events/
[dc-token]: https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html
[dc-audit]: https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html
[dc-rest]: https://support.atlassian.com/bitbucket-data-center/kb/how-to-retrieve-all-audit-entries-using-the-audit-log-api-in-bitbucket-server-and-data-center/
