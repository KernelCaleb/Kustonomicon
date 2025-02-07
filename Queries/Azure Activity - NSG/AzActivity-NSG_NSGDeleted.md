# Name

### Description
...

### Query
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE"
| where ActivityStatusValue == "Success"
| extend props = parse_json(Properties)
| extend
    entity = props.entity,
    NSG = props.resource
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, NSG, entity
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes