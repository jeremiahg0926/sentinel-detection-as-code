# Sentinel Detection-as-Code

KQL detection rules for Microsoft Sentinel, managed as YAML and shipped through
a CI/CD pipeline with infrastructure as code. Each rule is proven against real
attacker behavior with Atomic Red Team, with evidence attached to every PR.

**Status: Sprint 2 of 5 (next). Sprint 1 completed Nov 8.**

## Planned architecture

- YAML rules → converter → ARM templates
- Rule format: [docs/rule-format.md](docs/rule-format.md), defined by [schemas/detection-rule.schema.json](schemas/detection-rule.schema.json)
- `validate.yml` runs on every pull request
- `deploy.yml` deploys to Sentinel on merge via OIDC (no stored secrets)
- Bicep in two layers: `core` (workspace, Sentinel, identity) and `lab`
  (disposable test VM)
- Atomic Red Team testing in an Azure lab VM
- Evidence (alert, matched event, sample event) attached to each detection PR

## Roadmap

- [x] Sprint 0: Foundations (Nov 2–8, completed Oct 29)
- [x] Sprint 1: Infrastructure as code (Nov 9–22, completed Nov 8): Bicep core + lab layers, self-configuring lab VM, one-command lab-up / lab-down
- [ ] Sprint 2: Rule format + CI validation (Nov 23–Dec 6)
- [ ] Sprint 3: Go live: deploy pipeline + first attack tests (Dec 14–27)
- [ ] Sprint 4: Scale across ATT&CK (Dec 28–Jan 10)
- [ ] Sprint 5: Polish, publish, tear down (Jan 11–24)

## Detection coverage

| Technique | Tactic | Rule | PR | Status |
| --- | --- | --- | --- | --- |
| T1059.001 PowerShell | Execution | | | Planned |
| T1136.001 Local account | Persistence | | | Planned |
| T1098 Account manipulation | Persistence | | | Planned |
| T1547.001 Registry run keys | Persistence | | | Planned |
| T1053.005 Scheduled task | Persistence | | | Planned |
| T1543.003 Windows service | Persistence | | | Planned |
| T1562.001 Impair defenses | Defense Evasion | | | Planned |
| T1070.001 Clear Windows event logs | Defense Evasion | | | Planned |
| T1218.011 Rundll32 | Defense Evasion | | | Planned |
| T1112 Modify registry | Defense Evasion | | | Planned |
| T1003.001 LSASS memory | Credential Access | | | Planned |
| T1087.001 Local account discovery | Discovery | | | Planned |
| T1082 System information discovery | Discovery | | | Planned |
| T1105 Ingress tool transfer | Command and Control | | | Planned |
| T1021.001 Remote Desktop Protocol | Lateral Movement | | | Planned |

## How it works

Coming in Sprint 3.

## Lab environment

A disposable Windows Server 2022 VM for attack testing, deployed into
`rg-dac-lab` as the deployment stack `stack-dac-lab`. It configures itself on
deploy: a managed Run Command runs `infra/lab/setup.ps1` as SYSTEM, which
installs Sysmon with a pinned sysmon-modular config, enables audit policy with
process command lines, and installs Atomic Red Team (pinned module versions and
atomics commit). The long-lived resources (workspace, DCR) live in `rg-dac-core`
and are never touched by the lab scripts.

**Prerequisites**

- PowerShell 7.2+
- Azure CLI with Bicep (`az bicep upgrade`)
- Signed in with `az login` to the subscription where `rg-dac-core` (tagged
  `project=dac`) and `rg-dac-lab` exist and `infra/core` is deployed
- Pester 5+, only to run the script tests

**Usage**

| Command | What it does |
| --- | --- |
| `./scripts/lab-up.ps1 [-WhatIf] [-AllowedIp <ip>] [-NoStart]` | Deploy or update the lab, start the VM, print a summary with the RDP address |
| `./scripts/lab-down.ps1 [-WhatIf] [-Force]` | Delete the stack and every resource it manages (`rg-dac-lab` itself is kept, empty) |
| `az vm deallocate --resource-group rg-dac-lab --name vm-dac-lab` | Pause between sittings without deleting anything; `lab-up` starts it again |

Auto-shutdown runs nightly at 23:30 Eastern as a safety net.

```powershell
./scripts/lab-up.ps1                            # RDP allowed from your detected public IP
./scripts/lab-up.ps1 -AllowedIp 203.0.113.10    # or from an explicit IP
./scripts/lab-down.ps1                          # lists resources, asks before deleting
```

**Secrets and the allowed IP**

`lab-up` detects your public IP (RDP is allowed from that `/32` only) and
prompts for the admin password unless `DAC_ADMIN_PASSWORD` is already set. Both
are passed to the deployment through `DAC_ALLOWED_IP` and `DAC_ADMIN_PASSWORD`
for the `az` call only, then restored to their previous values (removed if they
were not set before), even if the deployment fails. The scripts never write
either value to disk.

**Connecting**

RDP as `.\dacadmin` to the address `lab-up` prints. It changes on every rebuild;
never commit it.

**Safety rails**

- Context check before any change: signed in, subscription `Enabled`, and
  `rg-dac-core` tagged `project=dac`. No subscription or tenant IDs are
  hardcoded.
- `lab-down` refuses to run if any stack resource is outside `rg-dac-lab`,
  asks for confirmation unless `-Force`, and verifies afterwards that the core
  workspace and DCR are still present.
- `-WhatIf` on both scripts. `lab-up -WhatIf` runs a what-if deployment; its
  output includes the subscription ID, so redact it before sharing.

**Measured timings (2026-11-08)**

| Operation | Time |
| --- | --- |
| Rebuild from nothing | 5 min 33 s |
| Start a deallocated lab | 2 min 18 s |
| Teardown | 7 min 12 s |
| Setup script, install path | about 66 s |
| First Sysmon events in the workspace | about 4 min after starting a deploy |

Ingestion while the lab runs: a few MB per hour, about 8 MB in the busiest hour
(fresh rebuild); Sysmon is most of it. Well under the workspace's 1 GB/day cap.

**Tests**

```powershell
Invoke-Pester ./scripts/lab-common.Tests.ps1 -Output Detailed
```

## Run the lab

Coming in Sprint 3.

## Lessons learned

Coming in Sprint 5.
