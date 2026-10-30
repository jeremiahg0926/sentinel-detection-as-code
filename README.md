# Sentinel Detection-as-Code

KQL detection rules for Microsoft Sentinel, managed as YAML and shipped through
a CI/CD pipeline with infrastructure as code. Each rule is proven against real
attacker behavior with Atomic Red Team, with evidence attached to every PR.

**Status: Sprint 0 of 5 (in progress)**

## Planned architecture

- YAML rules → converter → ARM templates
- `validate.yml` runs on every pull request
- `deploy.yml` deploys to Sentinel on merge via OIDC (no stored secrets)
- Bicep in two layers: `core` (workspace, Sentinel, identity) and `lab`
  (disposable test VM)
- Atomic Red Team testing in an Azure lab VM
- Evidence (alert, matched event, sample event) attached to each detection PR

## Roadmap

- [ ] Sprint 0: Foundations (Nov 2–8)
- [ ] Sprint 1: Infrastructure as code (Nov 9–22)
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

## Run the lab

Coming in Sprint 3.

## Lessons learned

Coming in Sprint 5.
