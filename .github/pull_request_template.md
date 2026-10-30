<!-- For non-detection PRs, delete this template and describe the change instead. -->

Closes #<issue number>
## Detection: <TXXXX.XXX> – <Technique name>
**Tactic:** <tactic> | **Severity:** <low/med/high>
**ATT&CK:** https://attack.mitre.org/techniques/<ID>/

### What this detects
<1–2 sentences: the attacker behavior and why it matters>

### Query logic
- Data source: <table / event ID>
- Key filters: <what and why>
- Threshold / window: <value and reasoning>

### Test evidence
- Atomic test: <TXXXX.XXX #N> – `<command run>`
- Run time (UTC): <timestamp>
- Alert screenshot: ![alert](docs/evidence/<ID>/alert.png)
- Matched event: ![event](docs/evidence/<ID>/event.png)
- Sample event: `tests/<ID>.json`

### False-positive review
- Baseline window: <N days>, hits: <count>
- Benign triggers + exclusions: <details>

### Known gaps / evasions
- <how this could be bypassed>

### Triage steps
1. <first check>
2. <second check>

- [ ] Validation workflow passing
- [ ] IDs redacted in screenshots
