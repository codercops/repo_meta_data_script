#!/usr/bin/env python3
"""
Two-stage repository analysis pipeline.

Runs the existing tools back to back on a single target, in order:

  Stage 1  ->  Repo_analysis_tool.py     (staged metadata / metrics pipeline)
  Stage 2  ->  stage2_llm_detector.py    (LLM / AI-authorship detection)

This orchestrator does not modify either tool. It only shells out to them
with the right arguments, one after the other, and collects their outputs
into the same directory.

Target handling
  - A local directory is analyzed on disk by both stages.
  - A GitHub URL: stage 1 clones + analyzes it; stage 2 uses its own GitHub
    API provider (owner/repo parsed from the URL).
  - A GitLab URL (gitlab.com or self-hosted): stage 1 clones + analyzes it;
    stage 2 uses its own GitLab API provider (project path parsed from the URL).

Examples
  python run_pipeline.py -i ./some/local/repo
  python run_pipeline.py -i https://github.com/owner/repo --github-token ghp_xxx
  python run_pipeline.py -i https://gitlab.com/group/sub/repo --gitlab-token glpat-xxx
  python run_pipeline.py -i https://git.company.com/team/repo --gitlab-token glpat-xxx
"""

import argparse
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
STAGE1_SCRIPT = os.path.join(HERE, "Repo_analysis_tool.py")
STAGE2_SCRIPT = os.path.join(HERE, "stage2_llm_detector.py")


def classify_target(target):
    """
    Work out what kind of target we were given and pull out the pieces each
    stage needs.

    Returns a dict with at least {"kind": "local" | "github" | "gitlab"}.
    """
    raw = target.strip().strip('"').rstrip("/")

    # A path that exists on disk always wins — treat it as a local repo.
    if os.path.isdir(raw):
        return {"kind": "local", "path": os.path.abspath(raw), "name": os.path.basename(os.path.abspath(raw))}

    # scp-style git remote: git@host:group/repo.git
    m = re.match(r"git@([^:]+):(.+)", raw)
    if m:
        host, path = m.group(1), m.group(2)
    else:
        parsed = urlparse(raw)
        host, path = parsed.netloc, parsed.path.lstrip("/")

    if not host:
        # Not an existing directory and not a URL we can parse.
        return {"kind": "unknown", "raw": raw}

    if path.endswith(".git"):
        path = path[:-4]
    path = path.strip("/")
    host_l = host.lower()

    if "github" in host_l:
        parts = [p for p in path.split("/") if p]
        project = "/".join(parts[:2])  # owner/repo
        api_url = "https://api.github.com" if host_l == "github.com" else f"https://{host}/api/v3"
        return {
            "kind": "github",
            "project": project,
            "api_url": api_url,
            "name": parts[-1] if parts else "repo",
        }

    # Default for any other host is GitLab (gitlab.com or self-hosted),
    # matching how both underlying tools treat unknown Git hosts.
    parts = [p for p in path.split("/") if p]
    return {
        "kind": "gitlab",
        "project": path,  # full nested group/sub/repo path
        "gitlab_url": f"https://{host}",
        "name": parts[-1] if parts else "repo",
    }


def build_stage1_cmd(args):
    cmd = [
        sys.executable, STAGE1_SCRIPT,
        "-i", args.input,
        "-o", args.output_dir,
        "-m", args.mode,
    ]
    if args.github_token:
        cmd += ["--github-token", args.github_token]
    if args.gitlab_token:
        cmd += ["--gitlab-token", args.gitlab_token]
    return cmd


def build_stage2_cmd(args, target):
    kind = target["kind"]
    out_csv = os.path.join(args.output_dir, f"{target.get('name', 'repo')}_llm_detection.csv")
    cmd = [sys.executable, STAGE2_SCRIPT, "--provider", kind, "--output", out_csv]

    if kind == "local":
        cmd += ["--path", target["path"]]
    elif kind == "github":
        cmd += ["--project", target["project"], "--github-url", target["api_url"]]
        if args.github_token:
            cmd += ["--token", args.github_token]
    elif kind == "gitlab":
        cmd += ["--project", target["project"], "--gitlab-url", target["gitlab_url"]]
        if args.gitlab_token:
            cmd += ["--token", args.gitlab_token]

    return cmd, out_csv


def run(cmd, label):
    print("\n" + "=" * 70)
    print(f"[{label}] {' '.join(cmd)}")
    print("=" * 70, flush=True)
    result = subprocess.run(cmd)
    print(f"[{label}] exit code: {result.returncode}", flush=True)
    return result.returncode


def main():
    ap = argparse.ArgumentParser(
        description="Run the stage 1 repo analysis, then the stage 2 LLM detector, on one target.")
    ap.add_argument("-i", "--input", required=True,
                    help="Local directory path OR a GitHub/GitLab repository URL")
    ap.add_argument("-o", "--output-dir", default="./outputs",
                    help="Where both stages write their reports (default: ./outputs)")
    ap.add_argument("-m", "--mode", choices=["stage1", "stage2", "full"], default="full",
                    help="Mode passed through to stage 1 (default: full)")
    ap.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"),
                    help="GitHub token for both stages (or set GITHUB_TOKEN)")
    ap.add_argument("--gitlab-token", default=os.environ.get("GITLAB_TOKEN"),
                    help="GitLab token for both stages (or set GITLAB_TOKEN)")
    ap.add_argument("--skip-stage1", action="store_true", help="Run only stage 2")
    ap.add_argument("--skip-stage2", action="store_true", help="Run only stage 1")
    args = ap.parse_args()

    args.input = args.input.strip().strip('"')

    for script in (STAGE1_SCRIPT, STAGE2_SCRIPT):
        if not os.path.isfile(script):
            sys.exit(f"[!] Required script not found: {script}")

    target = classify_target(args.input)
    if target["kind"] == "unknown":
        sys.exit(f"[!] Could not classify target (not a local dir, not a parseable URL): {args.input}")

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Target   : {args.input}")
    print(f"Detected : {target['kind']}"
          + (f" (project: {target.get('project')})" if target.get("project") else "")
          + (f" (path: {target.get('path')})" if target.get("path") else ""))
    print(f"Output   : {os.path.abspath(args.output_dir)}")

    rc1 = 0
    if not args.skip_stage1:
        rc1 = run(build_stage1_cmd(args), "Stage 1: Repo_analysis_tool")
        if rc1 != 0:
            print("[warn] Stage 1 returned a non-zero exit code; continuing to stage 2 anyway.")

    rc2 = 0
    stage2_csv = None
    if not args.skip_stage2:
        stage2_cmd, stage2_csv = build_stage2_cmd(args, target)
        if target["kind"] in ("github", "gitlab") and not (args.github_token or args.gitlab_token):
            print(f"[warn] Stage 2 will hit the {target['kind']} API without a token; "
                  "it may be rate limited. Pass --github-token / --gitlab-token or set the env var.")
        rc2 = run(stage2_cmd, "Stage 2: llm_detector")

    print("\n" + "=" * 70)
    print("PIPELINE SUMMARY")
    print("=" * 70)
    print(f"  Stage 1 exit : {rc1}{' (skipped)' if args.skip_stage1 else ''}")
    print(f"  Stage 2 exit : {rc2}{' (skipped)' if args.skip_stage2 else ''}")
    print(f"  Output dir   : {os.path.abspath(args.output_dir)}")
    if stage2_csv:
        print(f"  Stage 2 CSV  : {stage2_csv}")

    sys.exit(1 if (rc1 or rc2) else 0)


if __name__ == "__main__":
    main()
