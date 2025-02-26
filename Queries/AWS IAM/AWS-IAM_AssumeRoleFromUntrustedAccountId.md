# Name

### Description
...

### Query
```kql
let InternalAccountIds = dynamic(["123", "456"]);
let TrustedExternalAccountIds = dynamic(["789"]);
AWSCloudTrail
| where EventName == "AssumeRole"
| extend accountId = parse_json(Resources).[0].accountId
| where accountId !in (InternalAccountIds) and accountId !in (TrustedExternalAccountIds)
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes