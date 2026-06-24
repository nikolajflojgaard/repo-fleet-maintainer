# Repo Fleet Maintainer

Skill and tooling for maintaining a fleet of local and GitHub repositories without trampling user work.

It started from a real maintenance pass across several active repos: stale Node dependency trees, missing deploy secrets, dirty worktrees, local-only repos, and repeated Astro upgrade risk. The pattern was useful enough to make repeatable.

## What It Does

- Discovers local Git repos from configured roots
- Classifies repo type
- Checks branch, remote, ahead/behind, and dirty status
- Tracks last commit age
- Optionally runs `npm audit`
- Optionally scans for obvious secret files and token patterns
- Buckets repos into `safe-fix`, `needs-review`, `blocked`, `cleanup-candidate`, and `watch`
- Produces JSON or Markdown output

## Quick Start

Read-only inventory:

```bash
python3 scripts/repo_fleet_scan.py ~/Documents --markdown
```

Deeper read-only sweep:

```bash
python3 scripts/repo_fleet_scan.py ~/Documents --audit-node --secret-scan --markdown
```

Actionable report only:

```bash
python3 scripts/repo_fleet_scan.py ~/Documents --markdown --only-actionable
```

With config:

```bash
python3 scripts/repo_fleet_scan.py --config examples/fleet-config.example.json --markdown
```

## Skill Contents

- `SKILL.md` - workflow instructions
- `scripts/repo_fleet_scan.py` - read-only scanner
- `templates/fleet-report.md` - final report template
- `templates/cleanup-plan.md` - safe cleanup review template
- `templates/repo-finding.json` - finding schema template
- `examples/fleet-report-example.md` - example output
- `examples/fleet-config.example.json` - example scanner config
- `docs/` - generated documentation

## Safety

The scanner does not modify repos. The skill instructs the hub to apply fixes only after authorization, commit only scoped files, preserve dirty worktrees, and separate breaking upgrades from low-risk fixes.

Cleanup candidates are suggestions only. The tool never deletes repositories.
