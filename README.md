# Repository Intelligence CLI Tool (v3.0.0)

A high-performance, multi-stage static analysis pipeline designed to transform raw codebases into actionable intelligence. This tool performs deep analysis on Git metadata, code metrics, architectural patterns, and security risks.

## 🛠️ Setup & Requirements

Follow these steps in order. Windows commands use PowerShell; macOS and Ubuntu/Linux commands use a Bash-style terminal.

### 1. Install Python

Ensure that Python 3.8 or newer is installed. You can verify it with:

```powershell
python --version
```

On macOS or Ubuntu/Linux, use:

```bash
python3 --version
```

### 2. Install `scc` (Required)

The tool uses `scc` for total repository LOC, authored/non-authored LOC,
comment/blank counts, language breakdowns, and the authored source-file token manifest.

[Click here to open the SCC installation guide.](./SCC_INSTALL.md)

The script requires exactly `scc` version `3.7.0`, so follow the guide carefully and install that version.

#### Verify Required Version

```bash
scc --version
```

If `scc` is missing or the installed version is not `3.7.0`, the script stops before analysis starts.

### 3. Download the tool

Clone this repository (this needs `git`, see [Git requirement](#git-requirement)):

```bash
git clone https://github.com/codercops/repo_meta_data_script.git
```

You can also use **Code → Download ZIP** on the GitHub page and extract it.

### 4. Open the `repo_meta_data_script` folder

Open the `repo_meta_data_script` folder in Visual Studio Code. Open a new terminal in VS Code using **Terminal → New Terminal**. The terminal starts in that folder.

If you use a plain terminal instead, run:

Windows:

```powershell
cd .\repo_meta_data_script\
```

macOS or Ubuntu/Linux:

```bash
cd ./repo_meta_data_script
```

### 5. Create a virtual environment

Windows:

```powershell
python -m venv venv
```

macOS or Ubuntu/Linux:

```bash
python3 -m venv venv
```

### 6. Activate the virtual environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

macOS or Ubuntu/Linux:

```bash
source venv/bin/activate
```

### 7. Install the required Python libraries

Windows:

```powershell
python -m pip install -r requirements.txt
```

macOS or Ubuntu/Linux:

```bash
python3 -m pip install -r requirements.txt
```

### 8. Configure your provider access token

Create a local `.env` file from the example file.

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

macOS or Ubuntu/Linux:

```bash
cp .env.example .env
```

Open `.env` and paste your token after the `=` for the version-control provider you use. For example, for GitHub only:

```text
GITHUB_TOKEN=github_pat_your_token_here
GITLAB_TOKEN=
BITBUCKET_TOKEN=
```

Leave the lines you don't need empty. Any text after `=` is sent as a real token, so a leftover placeholder makes cloning and the API calls fail. Do not share your tokens or commit `.env` to the repository.

### 9. Prepare the project CSV file

Create `projects.csv` from the example file.

Windows PowerShell:

```powershell
Copy-Item projects.example.csv projects.csv
```

macOS or Ubuntu/Linux:

```bash
cp projects.example.csv projects.csv
```

Open `projects.csv`. Keep the first row, which is the header, and remove the three example data rows. Then add one row for each repository you want to analyze:

```csv
project_name,repo_url,branch
Payment Platform,https://github.com/company/payment-api.git,main
Payment Platform,https://github.com/company/payment-ui.git,develop
```

The `branch` column and an exact branch name are required for every repository row in project mode. Leaving the branch blank or removing the column causes validation to fail. Use the same `project_name` for repositories that belong to the same project.

> **Note:** If you want to skip **PR/MR Analytics** and analyze repositories that are already cloned locally, enter the local repository path in the `repo_url` column. For example: `Payment Platform,D:\All Repositories\payment-api,main`. Remove the provider token values from `.env` before running the analysis. The tool will still perform local analysis, including LOC and repository structure metrics.

### 10. Run the analysis

Windows:

```powershell
python Repo_analysis_tool.py --projects projects.csv --mode full
```

macOS or Ubuntu/Linux:

```bash
python3 Repo_analysis_tool.py --projects projects.csv --mode full
```

### Git requirement

Ensure `git` is installed and available in your terminal so the tool can clone remote repositories and analyze commit history.

```bash
git --version
```

## 📖 Usage

### Recommended usage: project analysis

After completing the setup steps and preparing `projects.csv`, run the following command:

```powershell
python Repo_analysis_tool.py --projects projects.csv --mode full
```

For macOS or Ubuntu/Linux, use the equivalent command shown in setup step 10.

Analysis resumes automatically from the last completed stage when the same
repository and options are run again. For Git repositories, a changed `HEAD`
invalidates the checkpoint, and so do uncommitted changes. Each repository's
checkpoint is a hidden `.analysis_checkpoint.json` file in its output folder
(`outputs/<repository>/` for a single run, `outputs/<project>/<repository>/` in
project mode). After a repository finishes, the file keeps only the finished
result, so running the same command again skips that repository. Use
`--no-resume` to ignore existing checkpoints and analyze everything from the
beginning.

### Project acceptance

For project-level acceptance, use a CSV with a required `branch` column:

```csv
project_name,repo_url,branch
Payment Platform,https://github.com/company/payment-api.git,main
Payment Platform,https://github.com/company/payment-ui.git,develop
Notification Service,https://github.com/company/notification-api.git,release/2.0
```

Rows with the same `project_name` are evaluated as one project. A project may
contain one or many repositories. A ready-to-copy file is available at
`projects.example.csv`.

Provide an exact branch name for every repository row. Blank or missing branch
values fail explicitly before analysis starts; the tool never silently falls back
to the default branch. For remote repositories, the requested branch is checked
out. For local repositories, the requested local branch is checked out (or a
tracking branch is created from an existing `origin/<branch>` ref), without
fetching or pulling. Checkout failures stop analysis; changes are never forcibly
discarded.

Each project keeps its own `legacy.csv`. The root output directory also receives
`combined_legacy.csv`, containing every declared project/repository in one file.
Its first columns are `Project Name`, `Repository Target`, and `Requested Branch`.
The combined file is replaced atomically on each portfolio run, so rows from an
older `projects.csv` do not remain in the latest result.

Repository-level rules apply to every repository: private visibility, no
detected license file/type, a meaningful root README, intact Git history, at
least 20 eligible source files, and at least two human contributors. Project-level rules require any one
repository to have at least 5,000 eligible source LOC, any one repository to
span six months from first to last commit, and the same repository to have at
least 100 merged PRs and 100 commits.

Project evaluation returns `ACCEPT`, `REJECT`, or `MANUAL_REVIEW`. Unavailable
API facts such as visibility or PR data produce `MANUAL_REVIEW`, not a false
rejection. JSON and CSV portfolio reports are written to the output directory.

### Optional provider API tokens

Pass the matching token when analyzing private repositories or when provider API
enrichment is needed:

```powershell
python Repo_analysis_tool.py -i https://github.com/company/repo.git --github-token YOUR_GITHUB_TOKEN
python Repo_analysis_tool.py -i https://gitlab.com/company/repo.git --gitlab-token YOUR_GITLAB_TOKEN
python Repo_analysis_tool.py -i https://bitbucket.org/company/repo.git --bitbucket-token YOUR_BITBUCKET_TOKEN
```

The same token flags can be used with project CSV mode:

```powershell
python Repo_analysis_tool.py --projects projects.csv --github-token YOUR_GITHUB_TOKEN
python Repo_analysis_tool.py --projects projects.csv --gitlab-token YOUR_GITLAB_TOKEN
python Repo_analysis_tool.py --projects projects.csv --bitbucket-token YOUR_BITBUCKET_TOKEN
```

## 🚀 Key Features

### 1. Multi-Stage Analysis Pipeline

The tool executes analysis in organized layers to ensure a separation between ground truth (verified tools) and heuristic estimates:

- **Stage 0 (Git Meta)**: Extracts all commits reachable from fetched refs, full commit messages, parents, ref associations, branches, tags, contributor diversity, active span, and history-integrity signals.
- **Stage 0.5 (PR/MR Analytics)**: Extracts PR counts, metadata, general comments, inline review comments, formal review/approval metadata, commit messages, changed-file metadata, and available patch text for GitHub, GitLab, and Bitbucket. All three providers write issue and CI/build-result artifacts when their APIs expose the data. Bitbucket Server/Data Center has no native repository issue API, so linked Jira issues require a separate Jira integration.
- **Stage 1 (Structure)**: Scans directory hierarchy for architectural signals and framework manifests.
- **Stage 2 (Deep Metrics)**: Calculates code, documentation, and configuration token counts (via `tiktoken`), plus cross-file code duplication. Reports expose repository tokens, PR tokens, and their grand total separately.
- **Stage 3 (AI Detection)**: Uses entropy and token distribution heuristics to identify AI-generated code.
- **Stage 4 (Intelligence)**: Categorizes Frontend vs. Backend logic, detects infrastructure (Databases, Cloud, APIs) at all depths, and evaluates documentation quality.
- **Stage 5 (Security)**: Scans for exposed credentials, AWS keys, and database connection strings.

### Supplemental extraction artifacts

Each repository output directory can contain:

- `git_history_<repository>.json`: commits reachable from all fetched refs, branches, tags, and explicit completeness limitations.
- `issues_<repository>.json`: available issues and issue comments for GitHub, GitLab, and Bitbucket Cloud; Bitbucket Server records the native-issue limitation.
- `ci_results_<repository>.json`: available GitHub Actions, GitLab pipeline/job, Bitbucket Cloud Pipelines, or Bitbucket Server build-status results.
- `tests_ci_inventory_<repository>.json`: detected test files, CI definitions, and retained test/coverage reports. Tests are not executed automatically.
- `all_prs_<repository>.json`: PR/MR metadata plus available comments, reviews, changed files, and patches.

No artifact claims absolute completeness. Deleted or unfetched Git objects,
provider-truncated patches, deleted collaboration content, and expired or
permission-restricted CI data cannot be recovered by the extractor.

### 2. Advanced Infrastructure Detection (v3.0.0)

- **Canonical Reporting**: Automatically groups database aliases (e.g., `postgres` and `postgresql` → `PostgreSQL`).
- **Greedy Scanning**: Peeks inside source code files (`.py`, `.js`, `.go`, etc.) to identify library imports and connection strings.
- **Full-Depth Scanning**: Recursively analyzes the entire repository without depth limits.

### 3. Professional CSV Reporting

Generates standardized CSV outputs for at-scale repository auditing:

- **`summary_all.csv`**: A comprehensive dataset featuring 40 parameters including contributor mapping, complexity, architectural splits, and security findings.
- **`summary_metadata.csv`**: A curated executive summary focused on commercial usage, security status, and core architectural labels.

*For a detailed breakdown of what each CSV column means, please refer to the [`csv_schema.md`](./csv_schema.md) document.*

### 4. Robust Input Handling

- **Quote-Resistant Paths**: Automatically strips double-quotes from paths pasted from Windows File Explorer ("Copy as path").
- **Batch Processing**: Supports a single `.txt` file containing a mix of local directory paths and remote Git URLs.

## 📊 Outputs

The tool generates professional-grade reports in the `./outputs` folder:

1. **`summary_all.csv`**: Master dataset for data processing and audit reporting.
2. **`summary_metadata.csv`**: Curated metadata report for executive review.
3. **`{repo}_report.json`**: Deep-dive technical breakdown for each analyzed repository.
4. **`legacy.csv`**: Per-repository acceptance and analysis summary. In project mode, each project has its own `legacy.csv`.
5. **`combined_legacy.csv`**: Root-level file containing all declared project and repository results from the current project run.
6. **`portfolio_decision_<timestamp>.json`**: Complete portfolio-level decision report in JSON format. The timestamp uses the format `YYYYMMDD_HHMMSS`.
7. **`portfolio_summary_<timestamp>.csv`**: Portfolio-level CSV summary showing each project's decision, each repository's decision, and failed or unknown rules.
8. **`origin_remote_cleanup.csv`**: Audit of `origin`-remote cleanup for remote clones, existing clones, and local repository paths. It records whether `origin` was present, removed, absent, or could not be removed.

---

*Developed for Advanced Repository Intelligence & Technical Auditing.*
