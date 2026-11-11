# Detection rule format

Each detection rule is a YAML file at
`detections/<tactic>/<TechniqueID>-<slug>.yaml`, one rule per file. The format
is defined by [`schemas/detection-rule.schema.json`](../schemas/detection-rule.schema.json),
and VS Code checks rule files against it as you type (Red Hat YAML extension,
wired up in [`.vscode/settings.json`](../.vscode/settings.json)). CI will check
every PR against the same schema (issue #22).

Each file becomes one `Microsoft.SecurityInsights/alertRules` resource with
kind `Scheduled`. Unknown keys are rejected at every level.

## Field reference

Durations use the short form `<number><unit>`, where the number has no leading
zero and the unit is `m`, `h` or `d` (pattern `^[1-9][0-9]*[mhd]$`), for
example `5m`, `1h`, `1d`.

| Field | Required | Type and allowed values | Default if omitted | ARM property | Notes |
| --- | --- | --- | --- | --- | --- |
| `id` | Yes | string, GUID (pattern `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`) | none (required) | resource name | Never change it. See [Rule IDs](#rule-ids). |
| `name` | Yes | string, at least 1 character | none (required) | `properties.displayName` | Name shown in Sentinel. |
| `description` | Yes | string, at least 1 character | none (required) | `properties.description` | What the rule detects and why it matters. |
| `severity` | Yes | `High`, `Medium`, `Low`, `Informational` | none (required) | `properties.severity` | |
| `queryFrequency` | Yes | duration | none (required) | `properties.queryFrequency` | How often the query runs. Converted to ISO 8601. |
| `queryPeriod` | Yes | duration | none (required) | `properties.queryPeriod` | How far back each run looks. Converted to ISO 8601. |
| `triggerOperator` | Yes | `gt`, `lt`, `eq`, `ne` | none (required) | `properties.triggerOperator` | Converted to `GreaterThan`, `LessThan`, `Equal`, `NotEqual`. |
| `triggerThreshold` | Yes | integer, 0 or more | none (required) | `properties.triggerThreshold` | Compared with the query's result count using `triggerOperator`. |
| `tactics` | Yes | array of at least 1 unique value: `Reconnaissance`, `ResourceDevelopment`, `InitialAccess`, `Execution`, `Persistence`, `PrivilegeEscalation`, `DefenseEvasion`, `CredentialAccess`, `Discovery`, `LateralMovement`, `Collection`, `Exfiltration`, `CommandAndControl`, `Impact` | none (required) | `properties.tactics` | ARM spelling, no spaces. |
| `relevantTechniques` | Yes | array of at least 1 unique string, pattern `^T[0-9]{4}(\.[0-9]{3})?$` (e.g. `T1059`, `T1059.001`) | none (required) | `properties.techniques` and `properties.subTechniques` | Split by the converter. |
| `query` | Yes | string, at least 1 character | none (required) | `properties.query` | The KQL query. Use `query: \|`. |
| `entityMappings` | Yes | array of at least 1 mapping object | none (required) | `properties.entityMappings` | |
| `entityMappings[].entityType` | Yes, in each mapping | `Account`, `Host`, `IP`, `Process`, `File`, `FileHash`, `RegistryKey`, `RegistryValue`, `URL`, `DNS` | none (required) | `entityMappings[].entityType` | |
| `entityMappings[].fieldMappings` | Yes, in each mapping | array of at least 1 object | none (required) | `entityMappings[].fieldMappings` | |
| `entityMappings[].fieldMappings[].identifier` | Yes, in each field mapping | string, at least 1 character | none (required) | `fieldMappings[].identifier` | Entity identifier, such as `FullName` or `HostName`. Not checked against `entityType`. |
| `entityMappings[].fieldMappings[].columnName` | Yes, in each field mapping | string, at least 1 character | none (required) | `fieldMappings[].columnName` | Query output column that supplies the value. |
| `enabled` | No | boolean | `true` | `properties.enabled` | Whether the rule is active after deployment. |
| `version` | No | string, `MAJOR.MINOR.PATCH` (pattern `^[0-9]+\.[0-9]+\.[0-9]+$`) | none | not sent to ARM | Project metadata only. |
| `suppressionEnabled` | No | boolean | `false` | `properties.suppressionEnabled` | If `true`, `suppressionDuration` is required. |
| `suppressionDuration` | No (see Notes) | duration | `5h` | `properties.suppressionDuration` | Required when `suppressionEnabled` is `true`. Converted to ISO 8601. Ignored while `suppressionEnabled` is false. |
| `incidentConfiguration` | No | object | none | `properties.incidentConfiguration` | If omitted, the converter applies the defaults of the fields below. |
| `incidentConfiguration.createIncident` | No | boolean | `true` | `incidentConfiguration.createIncident` | Whether alerts create incidents. |
| `incidentConfiguration.groupingConfiguration` | No | object | none | `incidentConfiguration.groupingConfiguration` | How related alerts are grouped into one incident. |
| `incidentConfiguration.groupingConfiguration.enabled` | No | boolean | `false` | `groupingConfiguration.enabled` | Whether alert grouping is on. |
| `incidentConfiguration.groupingConfiguration.reopenClosedIncident` | No | boolean | `false` | `groupingConfiguration.reopenClosedIncident` | Whether a matching alert reopens a closed incident. |
| `incidentConfiguration.groupingConfiguration.lookbackDuration` | No | duration | `5h` | `groupingConfiguration.lookbackDuration` | Time window for grouping. Converted to ISO 8601. Ignored while grouping is off. |
| `incidentConfiguration.groupingConfiguration.matchingMethod` | No | `AllEntities`, `AnyAlert`, `Selected` | `AllEntities` | `groupingConfiguration.matchingMethod` | If `Selected`, `groupByEntities` needs at least one entry. |
| `incidentConfiguration.groupingConfiguration.groupByEntities` | No (see Notes) | array of unique values from the `entityType` list above | none | `groupingConfiguration.groupByEntities` | Required, with at least 1 entry, when `matchingMethod` is `Selected`. |

The defaults are applied by the converter (issue #21), not by the schema, so every generated ARM template contains a complete, explicit configuration.

## What the converter changes

- **Durations** go from the short form to ISO 8601: `5m` becomes `PT5M`, `1h`
  becomes `PT1H`, `1d` becomes `P1D`. This applies to `queryFrequency`,
  `queryPeriod`, `suppressionDuration` and
  `incidentConfiguration.groupingConfiguration.lookbackDuration`.
- **`triggerOperator`** goes from `gt`, `lt`, `eq`, `ne` to `GreaterThan`,
  `LessThan`, `Equal`, `NotEqual`.
- **`relevantTechniques`** is split in two: parent IDs (e.g. `T1059`) go to ARM
  `techniques`, and sub-technique IDs (e.g. `T1059.001`) go to `subTechniques`.
- **`version`** is not sent to ARM.

## Rules that depend on other fields

The schema enforces these with `if`/`then`:

- If `suppressionEnabled` is `true`, `suppressionDuration` is required.
- If `incidentConfiguration.groupingConfiguration.matchingMethod` is
  `Selected`, `groupByEntities` is required and must have at least one entry.

## What the schema does not check

The converter will check these (issue #21):

- Allowed ranges for durations. The schema only checks the format, so `999d`
  passes the schema.
- Whether an `identifier` is valid for its `entityType` (for example, that
  `HostName` is used with `Host`).

## Rule IDs

Generate the ID once, when you create the rule:

```powershell
[guid]::NewGuid()
```

Never change it afterwards. The ID becomes the ARM resource name, so changing
it deploys a duplicate rule instead of updating the existing one.

## YAML tips

- Indent with spaces only. YAML does not allow tabs.
- Use a literal block, `query: |`, for KQL. It keeps line breaks exactly as
  written.
- Use a folded block, `description: >-`, for long text. It joins lines with
  spaces and drops the final newline.
- Quote strings that YAML could read as another type: `yes`, `no`, `on`, `off`,
  and values that start with special characters such as `*` or `&`.

## Skeleton rule

Every required field, with placeholder values. Replace the all-zero `id` with a
new GUID.

```yaml
id: 00000000-0000-0000-0000-000000000000
name: Rule name
description: >-
  What the rule detects and why it matters.
severity: Medium
queryFrequency: 5m
queryPeriod: 5m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1059.001
query: |
  // your KQL here
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
```

A complete example that validates against the schema lives at
`tests/fixtures/valid-rule.yaml`.
