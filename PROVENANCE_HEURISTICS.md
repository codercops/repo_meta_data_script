# Public-exposure provenance estimate

On every run, `provenance.json` includes
`public_exposure_estimate`: an **estimate, not a confirmed finding**. It contains
`likelihood_percent`, a versioned scoring model, every signal's observed value,
source, weight, actual point contribution, explanation, and coverage gaps.
The percentage is an assumption-based exposure index, **not an empirically
calibrated probability**. It cannot certify that code was always private.

## When it runs

The provenance estimate runs whether or not audit records are available. It also
runs when audits are disabled/not requested, offline, permission denied, rate
limited, unsupported, malformed, or incomplete. The audit reason and original
audit check statuses are retained. No additional token scope is required, and
no new network requests are introduced by the heuristic itself.

A successful audit read, including an empty result, does not suppress provenance
scoring. Audit events are excluded from the heuristic score so a confirmed
transition does not inflate the independent provenance estimate. A matching
audit event can separately confirm exposure. An accessible audit still covers
only retained/returned records; it does not verify lifetime privacy.
Use `--provenance-audit-log` in the main CLI or `--audit-log` in the standalone CLI
to attempt organization audits before falling back. Personal GitHub repositories
do not use browser Security-log collection; public and local provenance signals
produce a labeled estimate and cannot verify lifetime privacy.

A clone with a usable original remote can still use provider APIs and audit
records if credentials permit. A clone without that access uses local signals.
Git itself retains no previous server visibility, list of everyone who cloned,
or complete hosting history. An audit on the supplied remote cannot rule out
earlier independent copies or mirrors.

## Collectible signals and access

| Signal | Limited-scope PAT/provider metadata | Clone/local files | Treatment |
| --- | --- | --- | --- |
| Current public/private flag | Yes, if repository metadata is readable; anonymous public check is separate | No | Public is strong; private never subtracts points |
| Fork relationship and public parent/source | Often available; hidden/deleted parents may be absent | Extra remotes can suggest an upstream | Public ancestry is stronger than an unverified fork flag |
| Stars, subscribers/watchers, forks | Available fields vary by provider; missing fields stay unavailable | No | Very weak; private collaboration can generate these |
| Public commit/search/archive matches | Optional anonymous GitHub search; bounded anonymous GitLab public-project search and per-project SHA lookup; Software Heritage GitLab origin visits | Local commit SHAs are compared with public candidates and archive snapshot branch tips | Exact match is strong for shared history, not by itself a visibility transition |
| Mirrors/public reference code | Existing public events/search may identify shared history | `--public-reference` compares supplied trees/commits | Supplied reference matches need public-origin verification |
| README/package links and extra remotes | Not required | Existing root README/manifests and remotes | Candidate upstreams only; linked repos are not automatically verified public mirrors |
| License artifacts and removal | Provider license metadata may be present | Root license text and bounded license-deletion history | Weak; dependencies and private projects may contain open-source licenses |
| README deletion | Not required | Up to 30 deletion commits across fetched refs | Weak; ordinary edits/deletions do not establish exposure |
| Large code tree with very short history | Not required | At least 100 tracked source files and 1–5 reachable commits | Weak import/squash lead; disabled for shallow/incomplete/altered history |
| Contributors/author metadata | Not required | Up to 1,000 commit author emails; report stores only distinct count | Context only, zero points; personal domains or many contributors do not imply publicity |
| Clone traffic | Usually insufficient access; not requested | Cannot recover other people's clones | Unavailable, zero points; recent traffic is not lifetime history |

GitHub's [repository endpoint](https://docs.github.com/en/rest/repos/repos#get-a-repository)
supports read-only metadata permissions and anonymous public resources. Its
`watchers_count` means stars; this model uses `subscribers_count` for watchers,
avoiding duplicate star counting. GitLab's
[Projects API](https://docs.gitlab.com/api/projects/) exposes visibility,
`forked_from_project`, `star_count`, and `forks_count` when accessible. Fields
unavailable on Bitbucket remain unknown rather than invented zeros.
GitHub [clone traffic](https://docs.github.com/en/rest/metrics/traffic#get-repository-clones)
requires stronger access and covers only the last 14 days; it is deliberately
excluded from scoring.

General web search, platform-wide GitLab commit search, The Stack membership,
fuzzy code similarity, domain ownership checks, signature trust, and arbitrary
README attribution edits are not implemented. GitLab checks automatically search
at most five public projects and compare at most five local commit hashes per
candidate. Software Heritage checks only the original GitLab URL (with and
without `.git`) and matching snapshot branch tips; missing archives are
inconclusive. The separate GitHub commit search remains opt-in
(`--provenance-search-commits` / `--search-public-commits`). All public lookup
requests are anonymous and send hashes or repo names, never source text or PATs.
Offline mode sends nothing.

## Weighted model v1

Weights are manually chosen assumptions. Strong public traces dominate; private
visibility and negative/missing search results never reduce the score. Counts
are binary (nonzero), so large popularity counts cannot dominate. Correlated
observations within a group contribute only their maximum; engagement adds its
three small weights.

| Group | Signal weights (percentage points) | Group cap |
| --- | --- | ---: |
| Public trace | Currently public 95; stable-ID historical public record 85; name-only historical record 40; exact public commit match 75; GitLab archived-origin snapshot match 75; public fork ancestor 60; supplied reference match 35 | 95 (strongest only) |
| Relationship | Fork flag 8 | 8 |
| Engagement | Nonzero stars 2 + subscribers 1 + forks 3 | 6 |
| Documentation | Deleted license 6; recognized root open-source license artifact 4; upstream links/additional remotes 3; deleted README 2 | 6 (strongest only) |
| History | Large tree with short complete history 4 | 4 |
| Context | Contributor count, clone history | 0 |

```text
likelihood_percent = min(99, sum(group_points))
```

There is no renormalization when signals are missing. Weak signals alone can
contribute at most 24 points. The upper cap avoids a 100% certainty claim.
Group maxima avoid stacking multiple observations of the same public trace or
documentation change. Groups can still correlate; this is another reason the
index is not a statistical probability. Calibration requires independently
labeled repositories and evaluation for false positives/negatives before any
probability interpretation or automated decision threshold.

For example, a 403 audit response, 50 stars, 8 subscribers, 3 forks, and a deleted
license produce **12%**: engagement 2 + 1 + 3 and documentation 6. A deleted README
adds zero further points because the documentation group already uses its
strongest signal. This is a low-weight collection of leads, not confirmation.

Each signal has `detected`, `not_detected`, or `unavailable` status.
`contribution_points` sums to `uncapped_points`; adding the report's
`cap_adjustment_points` reproduces the final percentage. Unavailable searches,
parents, and metrics stay visible in `coverage.unavailable_signals`. Local scans
are bounded and inspect only fetched history and supported file patterns.
**0% means no weighted indicators observed, not a 0% probability of publication.**
If no scored observations can be collected, the percentage is null rather than
a fabricated number.

## Reports and decisions

The main JSON report embeds the full result. CSV reports add
`public_exposure_estimate_status`, `public_exposure_estimate_percent`, and
`public_exposure_estimate_reason`; the console explicitly says "heuristic; not
confirmed". Project JSON metrics retain the percentage and estimate status.
When audits are available, estimate status is still `ESTIMATE`; the audit reason
is `audit_read_succeeded_within_retention` or `matching_audit_finding`.
`provenance_reasons` lists evidence kinds and contributing heuristic signals,
prefixed with `heuristic:` so estimated clues remain distinct from findings.

The heuristic never sets `ever_public`, `public_to_private_transition`, or
`always_private_verified`, and never changes the procurement decision. Confirmed
findings still reject; unverified provenance remains manual review regardless
of this percentage. Existing independently collected evidence can coexist with
an estimate and retains its original strength.
