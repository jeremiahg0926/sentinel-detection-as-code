# CLAUDE.md

Standing instructions for Claude Code in this repository.

## Project context

This is a public portfolio repo demonstrating detection-as-code for Microsoft
Sentinel. KQL detection rules are stored as YAML, validated in CI with GitHub
Actions, and deployed to Sentinel via OIDC federated credentials (no stored
secrets). Azure infrastructure is defined in Bicep, and every rule is tested
end to end by running Atomic Red Team against an Azure lab VM, with evidence
(alert and event screenshots, sanitized sample events) attached to each PR.

## Ground rules

- The repo owner writes all KQL detection logic. You may review KQL and
  explain it, but never write or rewrite detection queries unless explicitly
  asked.
- You may write tooling: scripts, workflows, Bicep, tests, docs.
- Explain every file you create or change, and why.
- Never commit, push, merge, or rebase. The repo owner does all git operations.
- Never add secrets, tenant IDs, subscription IDs, real IPs, or any employer
  data. Use placeholders like `<SUBSCRIPTION_ID>`, `<TENANT_ID>`,
  `<WORKSPACE_NAME>`.
- Prefer PowerShell 7 for scripts (CI runs `pwsh` on Linux runners).
- Before running any `gh`, `az`, or destructive shell command, show it and
  wait for approval.

## Conventions

- Rule files: `detections/<tactic>/<TechniqueID>-<short-slug>.yaml`
  (e.g. `detections/execution/T1059.001-encoded-powershell.yaml`)
- Branches: `detection/<TechniqueID>-<slug>`, `chore/<topic>`,
  `infra/<topic>`, `ci/<topic>`, `docs/<topic>`
- Commits: Conventional Commits, e.g.
  - `feat(detection): add T1136.001 local account creation`
  - `chore: ...`, `ci: ...`, `infra: ...`, `docs: ...`
- Evidence: `docs/evidence/<TechniqueID>/` (`alert.png`, `event.png`)
- Sample events: `tests/<TechniqueID>.json` (sanitized)
- One detection per PR, using the PR template.

## Repo layout

```text
.
├── .github/          PR template and issue forms (workflows arrive in Sprint 2)
├── .vscode/          Recommended editor extensions
├── detections/       KQL detection rules as YAML, grouped by ATT&CK tactic
├── docs/
│   ├── evidence/     Per-technique alert/event screenshots from lab tests
│   └── journal.md    Sprint-by-sprint learning log
├── infra/
│   ├── core/         Bicep for long-lived resources (workspace, Sentinel, identity)
│   └── lab/          Bicep for the disposable attack-test VM
├── scripts/          PowerShell 7 tooling (validation, YAML-to-ARM conversion)
└── tests/            Sanitized sample events, one JSON file per technique
```
