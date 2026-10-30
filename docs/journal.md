# Journal

A learning log: three sentences per sprint review (one each for Did, Learned, and Confused by).

<!--
Entry format:

## YYYY-MM-DD: Sprint N
**Did:**
**Learned:**
**Confused by / open questions:**
-->

## 2026-10-29: Sprint 0
**Did:** 
- Scoped the project as 15 MITRE ATT&CK techniques across 7 tactics
and built the backlog as GitHub issues with sprint milestones. Created the
repo and scaffold, and protected `main` with a ruleset so every change goes
through a pull request.
**Learned:** 
- Pushing to an empty repo makes the first branch the default. My scaffold
  branch became the main line, so I renamed it to `main`.
- `git` works on my local repo; `gh` talks to GitHub (issues, PRs, labels).
- PowerShell 5.1 is built into Windows; CI runs PowerShell 7. 5.1 defaults
  to UTF-16 output, which can break YAML/JSON files.
- Using a GitHub environment in the deploy workflow would change what GitHub
  presents to Azure during sign-in, so the federated credential has to match.

**Confused by / open questions:**
- How Bicep, the data collection rule, and the Azure Monitor Agent fit
  together. Sprint 1 should answer this.
- How OIDC proves GitHub's identity to Azure without a stored secret.
