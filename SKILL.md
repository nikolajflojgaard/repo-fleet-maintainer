---
name: repo-fleet-maintainer
description: Maintain a fleet of local/GitHub repositories with dependency audits, CI/deploy checks, dirty-worktree protection, secret scans, safe small fixes, documentation checks, and concise reports; use when the user asks to review, clean up, secure, update, or monitor multiple repos.
---

# Repo Fleet Maintainer

Use this skill when the user wants multiple repositories checked, maintained, secured, documented, or kept healthy over time.

The goal is safe, boring maintenance: find issues, apply low-risk fixes only when authorized, protect user work, and produce a concise report that makes the next action obvious.

## Default Posture

- Read-only first.
- Preserve dirty worktrees.
- Small safe fixes beat broad rewrites.
- Breaking upgrades become review items, not surprise commits.
- Public/external actions require explicit approval unless already authorized.
- The hub remains accountable for commits, pushes, CI status, and final claims.

## Quick Start

Use the bundled scanner for the first pass:

```bash
python3 scripts/repo_fleet_scan.py ~/Documents --markdown
```

Add optional checks when the user has authorized a deeper sweep:

```bash
python3 scripts/repo_fleet_scan.py ~/Documents --audit-node --secret-scan --markdown
```

The scanner is read-only. It reports repo type, dirty status, remotes, ahead/behind state, Node audit counts, lightweight secret findings, and recommended action buckets.

## Workflow

1. **Discover repos**
   - Start from configured roots such as `~/Documents` or a user-provided path.
   - Find Git repos without descending into nested dependency folders.
   - Record remote, branch, ahead/behind state, and dirty status.

2. **Classify repo type**
   - Node: `package.json`, lockfile, npm scripts.
   - Python: `pyproject.toml`, `requirements.txt`, setup files.
   - Static site: Astro, Vite, Next, Hugo, etc.
   - Home Assistant integration: `custom_components`, HACS metadata.
   - Skill repo: `SKILL.md`, templates, docs.
   - Unknown: report only unless clear checks exist.

3. **Run read-only health checks**
   - `git status --short --branch`
   - dependency audit where supported
   - CI/deploy status where GitHub remote exists
   - obvious secret-file and token-pattern scan
   - docs/config presence checks
   - build/test command discovery

4. **Plan fixes**
   Classify each finding:
   - `safe-fix`: lockfile-only or config-only fix with low blast radius.
   - `needs-review`: breaking upgrade, dirty worktree, missing secret, failed deploy, unclear ownership.
   - `blocked`: missing auth, missing remote, failing baseline, unknown dependency manager.
   - `watch`: low risk, no immediate action.

5. **Apply fixes only when authorized**
   - Pull/rebase first on clean shared branches.
   - Touch only scoped files.
   - Do not revert unrelated changes.
   - Commit only the files owned by the maintenance task.
   - Push only after validation.

6. **Validate**
   - Run the repo's strongest practical check: build, test, lint, docs check, or smoke command.
   - If full validation cannot run, run the best narrower validation and state the gap.
   - For GitHub repos, check workflow results after push when workflows exist.

7. **Report**
   Keep reports short and action-oriented:
   - repos fixed
   - commits pushed
   - checks passed/failed
   - remaining risks
   - blocked items
   - recommended next pass

## Dirty Worktree Rules

- Never clean, reset, checkout, or overwrite unrelated user changes.
- If a repo is dirty, only commit files directly owned by the maintenance task.
- If generated files change during validation, restore only files created/changed by the maintenance task and preserve pre-existing dirty files.
- If safe separation is impossible, stop and report.

## Node Repo Checks

Use when `package.json` exists:

- `npm audit --omit=dev --audit-level=moderate` when a lockfile exists.
- `npm audit fix` only for authorized non-breaking fixes.
- Do not run `npm audit fix --force` without a separate upgrade plan.
- Run `npm run build`, `npm test`, or project-specific validation if present.
- Report remaining advisories that require breaking upgrades.

## Python Repo Checks

Use when Python packaging files exist:

- Inspect declared dependencies.
- Use `pip-audit` only if available or already part of the environment.
- Do not install global tools just to complete a sweep unless the user approves.
- Prefer project-local virtualenvs for deeper checks.

## GitHub/CI Checks

Use GitHub CLI when a GitHub remote exists:

- Check recent workflow runs.
- Pull failed logs for relevant failures.
- Distinguish build failures from missing secrets or deploy credentials.
- Do not change secrets or deployment credentials without explicit approval.

## Secret Scan

Run a lightweight scan excluding `.git`, `node_modules`, `dist`, generated artifacts, and backups.

Look for:

- `.env` files
- private keys
- GitHub tokens
- OpenAI/API tokens
- cloud provider keys
- Slack/Discord/webhook tokens

Treat matches as sensitive. Do not paste secrets into chat. Report file path and type only.

## Report Template

Use `templates/fleet-report.md` for the final report.

```text
Repo fleet maintenance complete.

Fixed:
- <repo>: <commit> <summary>

Validated:
- <repo>: <check result>

Needs review:
- <repo>: <reason>

Blocked:
- <repo>: <reason>

Next recommended pass:
- <specific next action>
```

## Scheduling

This workflow is suitable for weekly or biweekly runs, but do not schedule it without explicit user approval.

Scheduled runs should default to report-only unless the user explicitly approves automatic safe fixes.
