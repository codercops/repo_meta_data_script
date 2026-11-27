# GitLab and Bitbucket historical visibility checks

For provider-by-provider token creation and audit permissions, see
[AUDIT_TOKEN_SETUP.md](./AUDIT_TOKEN_SETUP.md).

Native provenance adapters now supplement GitHub checks. All keep the same
conservative decision policy: explicit public evidence can reject a submission;
unavailable or ambiguous history requires manual review.

| Platform | Live audit source | Import source |
| --- | --- | --- |
| GitLab.com / Self-Managed | Project Audit Events API | Native audit-event JSON/JSONL, including streaming/export records with supported fields |
| Bitbucket Cloud | Atlassian organization events API | Native Atlassian organization event exports |
| Bitbucket Data Center | Cross-product auditing REST API | Native audit JSONL files or REST exports |

These integrations read retained records. They cannot reconstruct missing logs
or certify lifetime privacy. They have been tested with provider-schema fixtures;
authenticated audits still require validation against your own deployment.

## Run the project analyzer

Configure the existing `GITLAB_TOKEN` or `BITBUCKET_TOKEN` in `.env` and run:

```powershell
python Repo_analysis_tool.py --projects projects.csv --mode full --provenance-audit-log
```

`--provenance-audit-log` now selects the native audit adapter for each repository.
The collector also obtains the current provider ID and visibility, checks an
anonymous response, and retains provider/instance identity in `provenance.json`
and the summary CSV columns `provenance_provider` and `provenance_instance_url`.
Missing visibility fields do not default to public.

### GitLab

GitLab project audit access is available on supported Premium/Ultimate plans.
Maintainer or higher can retrieve project audit records for all users; Developer
access can be restricted to the caller's own actions. Use a token with the
appropriate API read access for your GitLab configuration. A token's scope does
not elevate the user's project role. Plan/permission failures are recorded.

The adapter reads `/api/v4/projects/<id>/audit_events` with a wide date filter,
keyset pagination and a five-page cap. It recognizes project visibility changes
from the explicit event type or `details.change`, with `details.from/to` values.
GitLab visibility values `public/private/internal` and `20/0/10` are distinguished;
an internal-to-private change is not treated as public exposure. Group changes
are not mistaken for project changes.

GitLab Free additionally runs bounded, anonymous public-reference checks on
every online provenance run. It searches public projects using the repository
name and GitLab links in root documentation/remotes, then verifies up to five
local commit SHAs in at most five public candidates with the per-project
Commits API. It also checks Software Heritage visits for the original GitLab
origin URL (with and without `.git`) and compares dated snapshot branch tips
with local commits. These requests do not send the GitLab PAT. A matching SHA
or archived snapshot is `PUBLIC_CODE_MATCH` evidence and contributes to the
heuristic score; it does not confirm that this exact project changed from
public to private. Missing results, inaccessible APIs and truncated searches
do not establish that it was always private. Offline mode skips all requests.

Standalone example (tokens come from process environment, not `.env`):

```powershell
python provenance.py --repo "D:\Submissions\payments" --repository-url "https://gitlab.com/vendor/payments" --audit-log --output-dir ".\outputs\payments-provenance"
```

### Bitbucket Cloud

A Bitbucket repository/workspace token is used for repository metadata. The
organization audit API is a separate Atlassian service and needs separate
organization admin access with the appropriate event-read authorization
(`read:events:admin` for scoped authorization). Event availability also depends
on the organization configuration and subscriptions.

Configure these locally for the main analyzer:

```dotenv
BITBUCKET_TOKEN=your_repository_or_workspace_access_token
ATLASSIAN_ORG_ID=your_atlassian_organization_id
ATLASSIAN_ADMIN_TOKEN=your_atlassian_admin_credential
```

The organization ID is not the Bitbucket workspace slug. The adapter reads
`https://api.atlassian.com/admin/v1/orgs/<orgId>/events`, follows the returned
next link/cursor for at most five pages, and matches repository UUIDs from
repository context objects. It does not send the Bitbucket token to the
Atlassian organization API or send the admin credential to Bitbucket.

Some events say only "Updated repository privacy setting" and do not expose
old/new values. Such a record becomes `native_visibility_change_unresolved`.
It is not enough to infer that a currently private repository was previously
public. Explicit `changedValues`/`changes` entries for `is_private`, `public` or
visibility can establish the direction when the deployment provides them.

### Bitbucket Data Center and self-hosted GitLab

Self-hosted IDs are local to their instance. Specify the trusted HTTPS instance
URL before the provenance collector sends a provider credential there. Include
any context path. Use a separate run for each self-hosted instance.

```powershell
python Repo_analysis_tool.py --projects projects.csv --provenance-audit-log --provenance-provider bitbucket_server --provenance-instance-url "https://code.example.com/bitbucket"
```

Standalone equivalent:

```powershell
python provenance.py --repo "D:\Submissions\payments" --repository-url "https://code.example.com/bitbucket/scm/PROJ/payments.git" --provider bitbucket_server --instance-url "https://code.example.com/bitbucket" --audit-log
```

Use `gitlab` for `--provenance-provider` / `--provider` on a self-hosted GitLab
instance. For GitLab.com and bitbucket.org, automatic provider detection is
available. Arbitrary self-hosted hostnames require an explicit provider.

Data Center reads `/rest/auditing/1.0/events`, filtered by repository ID, with
cursor/next-link pagination capped at five pages. Access depends on admin rights,
version, audit coverage and retained events. The parser supports the modern
`affectedObjects` + `changedValues` audit representation, including `type` and
`typeName` repository objects. It does not use the legacy audit endpoints removed
from newer Bitbucket versions. A repository `Public` true-to-false change means
public-to-private; Cloud's `is_private` field has the opposite polarity.

The explicit instance restriction applies to the new provenance requests. The
legacy full-pipeline clone/PR/MR integrations retain their existing provider
authentication behavior. Use the standalone entry point to limit a run to the
new scoped provenance clients.

## Import provider exports

Existing `--provenance-evidence` (main analyzer) and `--evidence` (standalone)
accept native provider exports. To bind instance-local IDs, wrap raw records
without editing their fields:

```json
{
  "provider": "gitlab",
  "instance_url": "https://gitlab.com",
  "events": [
    {
      "id": 111,
      "entity_type": "Project",
      "entity_id": 42,
      "created_at": "2020-04-01T10:00:00Z",
      "details": {
        "change": "visibility level",
        "from": "Public",
        "to": "Private"
      }
    }
  ]
}
```

Use `bitbucket_cloud` with `https://bitbucket.org`, or `bitbucket_server` with
the exact Data Center instance/context URL. The events can also contain native
API response envelopes (`data`, `entities`, `values`), which are unpacked.
JSONL can contain one provider/instance envelope per line. Raw unscoped native
records are accepted as leads, but matching numeric IDs alone cannot establish
which instance produced them. Conflicting provider, instance or repository IDs
never confirm exposure.

The current provider ID normally comes from its live metadata API; supplying an
original repository URL alone does not authenticate that ID. Fully offline runs
without a verified identity remain unresolved. Imported files are hashed and
recognized raw events receive fingerprints; these support traceability, not
authenticity. Independently verify vendor-supplied exports before alleging a
visibility conversion.

GH Archive SQL is generated only for GitHub identities. GitLab/Bitbucket numeric
IDs are never used in GitHub archive queries or compared with GitHub repository
IDs. Local source/history comparisons continue to work across all providers.

## Official references

- [GitLab Audit Events API](https://docs.gitlab.com/api/audit_events/)
- [GitLab audit event types](https://docs.gitlab.com/user/compliance/audit_event_types/)
- [Atlassian organization events API](https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events/)
- [Atlassian audit activity catalog](https://support.atlassian.com/security-and-access-policies/docs/audit-log-activities-database/)
- [Bitbucket Data Center audit retrieval](https://support.atlassian.com/bitbucket-data-center/kb/how-to-retrieve-all-audit-entries-using-the-audit-log-api-in-bitbucket-server-and-data-center/)
- [Cross-product audit response schema](https://developer.atlassian.com/server/framework/atlassian-sdk/rest/api-group-events/)
