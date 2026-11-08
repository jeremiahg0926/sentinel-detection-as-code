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

## 2026-11-08: Sprint 1
**Did:**
- Built the infrastructure in Bicep in two layers: `core` (Log Analytics
  workspace, data collection rule, Sentinel switched off until Sprint 3) and
  `lab` (a disposable Windows Server VM deployed as a deployment stack). The
  lab sets itself up on deploy: a Run Command installs Sysmon, sets the audit
  policy and installs Atomic Red Team, all pinned and hash-checked.
  `lab-up` / `lab-down` rebuild it from nothing in about 5.5 minutes and tear
  it down in about 7 without touching core.

**Learned:**
- The Azure Monitor Agent only listens to event logs that exist when it
  starts. Sysmon installed after the agent sent nothing until a reboot. I
  fixed it by ordering (setup runs before the agent is installed) and proved
  it by rebuilding the lab from scratch.
- To prove a fix, recreate the conditions that broke it. Updating the
  existing VM couldn't test the ordering; only a fresh rebuild could. My KQL
  filtered on time because the old VM had the same name.
- Pin and verify anything downloaded: a release tag and SHA-256 for the
  Sysmon config, a signature check for the Sysmon binary, exact module
  versions and a commit hash for Atomic Red Team. Upstream moved under me
  once (sysmon-modular), and the pins made it obvious.
- Atomic Red Team needs a Defender exclusion, and adding one is itself an
  attacker technique (T1562.001, event 5007), so it's baseline in my lab and
  a future detection.
- An unchanged Run Command doesn't run again on redeploy; it only re-runs
  when the script changes. I measured this; the docs don't say.
- Unit-test the guardrails, integration-test the Azure parts: 36 Pester
  tests on the helpers, real deploys and deletes for the rest.

**Confused by / open questions:**
- Answered from Sprint 0: Bicep deploys the DCR and the agent, the DCR says
  which events to collect, the agent ships them to the workspace, and the
  order they start in matters.
- PowerShell surprises: `(& $block).Count` fails under StrictMode when there
  are no results (fix: `@(& $block).Count`), and passing `$null` to a .NET
  `[string]` parameter turns it into an empty string, which left my admin
  password in the session after a `-WhatIf` run until a test caught it.
- Still open: how OIDC proves GitHub's identity to Azure (Sprint 3), and how
  to route Security events into the `SecurityEvent` table once Sentinel is
  on (#23).
