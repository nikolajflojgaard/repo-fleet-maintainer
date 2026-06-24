#!/usr/bin/env python3
"""Read-only repo fleet scanner.

The script intentionally does not fix anything. It discovers repositories,
classifies them, checks Git state, optionally runs npm audit, and optionally
performs a lightweight secret-pattern scan.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".astro",
    ".venv",
    "venv",
    "__pycache__",
    "backups",
    "release",
}

SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----")),
    ("github-token", re.compile(r"(ghp_|github_pat_)[A-Za-z0-9_]{20,}")),
    ("openai-token", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    (
        "generic-secret",
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}"),
    ),
]


@dataclass
class RepoReport:
    path: str
    name: str
    branch: str = ""
    dirty: bool = False
    ahead: int | None = None
    behind: int | None = None
    remote: str = ""
    types: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    audit: dict[str, Any] | None = None
    secret_findings: list[dict[str, str]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    recommendation: str = "watch"


def run(cmd: list[str], cwd: Path, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def discover_repos(roots: list[Path], max_depth: int) -> list[Path]:
    repos: list[Path] = []
    seen: set[Path] = set()

    def walk(path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        if path.name in EXCLUDED_DIRS:
            return
        if (path / ".git").is_dir():
            resolved = path.resolve()
            if resolved not in seen:
                repos.append(resolved)
                seen.add(resolved)
            return
        try:
            children = sorted(p for p in path.iterdir() if p.is_dir())
        except (OSError, PermissionError):
            return
        for child in children:
            walk(child, depth + 1)

    for root in roots:
        walk(root.expanduser().resolve(), 0)
    return sorted(repos)


def classify_repo(repo: Path) -> tuple[list[str], dict[str, str]]:
    types: list[str] = []
    scripts: dict[str, str] = {}

    package_json = repo / "package.json"
    if package_json.exists():
        types.append("node")
        try:
            package = json.loads(package_json.read_text())
            scripts = dict(package.get("scripts") or {})
            deps = {**(package.get("dependencies") or {}), **(package.get("devDependencies") or {})}
            if "astro" in deps:
                types.append("astro")
            if "vite" in deps or "@vitejs/plugin-react" in deps:
                types.append("vite")
            if "next" in deps:
                types.append("next")
        except (OSError, json.JSONDecodeError):
            types.append("node-unreadable-package")

    if any((repo / name).exists() for name in ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"]):
        types.append("python")
    if (repo / "custom_components").is_dir() or (repo / "hacs.json").exists():
        types.append("home-assistant")
    if (repo / "SKILL.md").exists():
        types.append("skill")
    if (repo / "code-docs.yml").exists() or (repo / "docs").is_dir():
        types.append("documented")

    return types or ["unknown"], scripts


def git_status(repo: Path) -> tuple[str, bool, int | None, int | None]:
    status = run(["git", "status", "--short", "--branch"], repo)
    lines = status.stdout.splitlines()
    branch = lines[0].replace("## ", "") if lines else ""
    dirty = any(line and not line.startswith("## ") for line in lines)

    ahead = behind = None
    rev = run(["git", "rev-list", "--left-right", "--count", "HEAD...@{upstream}"], repo)
    if rev.returncode == 0:
        parts = rev.stdout.strip().split()
        if len(parts) == 2:
            ahead, behind = int(parts[0]), int(parts[1])
    return branch, dirty, ahead, behind


def git_remote(repo: Path) -> str:
    remote = run(["git", "remote", "get-url", "origin"], repo)
    return remote.stdout.strip() if remote.returncode == 0 else ""


def npm_audit(repo: Path) -> dict[str, Any] | None:
    if not (repo / "package-lock.json").exists():
        return None
    result = run(["npm", "audit", "--omit=dev", "--audit-level=moderate", "--json"], repo, timeout=90)
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {"error": "npm audit returned non-json output"}
    vulnerabilities = payload.get("metadata", {}).get("vulnerabilities", {})
    return {
        "exit_code": result.returncode,
        "vulnerabilities": vulnerabilities,
    }


def should_scan(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return False
    if path.stat().st_size > 750_000:
        return False
    return path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".ico"}


def secret_scan(repo: Path, max_findings: int = 20) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for filename in files:
            path = Path(root) / filename
            rel = path.relative_to(repo)
            if filename.startswith(".env"):
                findings.append({"type": "env-file", "path": str(rel)})
                if len(findings) >= max_findings:
                    return findings
            try:
                if not should_scan(path):
                    continue
                text = path.read_text(errors="ignore")
            except (OSError, UnicodeError):
                continue
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    findings.append({"type": label, "path": str(rel)})
                    break
            if len(findings) >= max_findings:
                return findings
    return findings


def recommendation(report: RepoReport) -> str:
    if report.secret_findings:
        return "needs-review"
    if report.dirty:
        return "needs-review"
    if report.audit:
        total = int(report.audit.get("vulnerabilities", {}).get("total") or 0)
        critical = int(report.audit.get("vulnerabilities", {}).get("critical") or 0)
        high = int(report.audit.get("vulnerabilities", {}).get("high") or 0)
        if critical:
            return "needs-review"
        if high or total:
            return "safe-fix"
    if not report.remote:
        return "blocked"
    return "watch"


def inspect_repo(repo: Path, audit_node: bool, scan_secrets: bool) -> RepoReport:
    branch, dirty, ahead, behind = git_status(repo)
    types, scripts = classify_repo(repo)
    report = RepoReport(
        path=str(repo),
        name=repo.name,
        branch=branch,
        dirty=dirty,
        ahead=ahead,
        behind=behind,
        remote=git_remote(repo),
        types=types,
        scripts=scripts,
    )
    if audit_node and "node" in types:
        report.audit = npm_audit(repo)
    if scan_secrets:
        report.secret_findings = secret_scan(repo)
    if not report.remote:
        report.findings.append("No origin remote configured.")
    if report.dirty:
        report.findings.append("Dirty worktree; preserve user changes.")
    if report.audit:
        total = report.audit.get("vulnerabilities", {}).get("total", 0)
        if total:
            report.findings.append(f"npm audit reports {total} vulnerabilities.")
    if report.secret_findings:
        report.findings.append("Potential secret findings need review.")
    report.recommendation = recommendation(report)
    return report


def markdown_report(reports: list[RepoReport]) -> str:
    lines = ["# Repo Fleet Report", ""]
    buckets = ["safe-fix", "needs-review", "blocked", "watch"]
    for bucket in buckets:
        items = [r for r in reports if r.recommendation == bucket]
        lines.append(f"## {bucket}")
        lines.append("")
        if not items:
            lines.append("- None")
            lines.append("")
            continue
        for report in items:
            dirty = "dirty" if report.dirty else "clean"
            audit = ""
            if report.audit:
                vulns = report.audit.get("vulnerabilities", {})
                audit = f", audit total {vulns.get('total', 0)}"
            remote = "remote" if report.remote else "no remote"
            lines.append(f"- **{report.name}** ({', '.join(report.types)}; {dirty}; {remote}{audit})")
            for finding in report.findings:
                lines.append(f"  - {finding}")
            for finding in report.secret_findings:
                lines.append(f"  - Potential {finding['type']} in `{finding['path']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only repo fleet scanner.")
    parser.add_argument("roots", nargs="*", default=["~/Documents"], help="Root directories to scan.")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum directory depth below each root.")
    parser.add_argument("--audit-node", action="store_true", help="Run npm audit for Node repos with lockfiles.")
    parser.add_argument("--secret-scan", action="store_true", help="Run a lightweight secret-pattern scan.")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown instead of JSON.")
    args = parser.parse_args()

    roots = [Path(root).expanduser() for root in args.roots]
    repos = discover_repos(roots, args.max_depth)
    reports = [inspect_repo(repo, args.audit_node, args.secret_scan) for repo in repos]

    if args.markdown:
        print(markdown_report(reports))
    else:
        print(json.dumps([report.__dict__ for report in reports], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
