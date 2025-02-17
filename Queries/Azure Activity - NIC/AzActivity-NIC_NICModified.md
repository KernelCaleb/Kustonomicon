# Azure Activity - NIC: NIC Modified

### Description
This query detects when a Network Interface Card is modified, sich as when a public IP address is added to the configuration.

### Query
```kql
AzureActivity
| where OperationNameValue contains "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE"
| where ActivityStatusValue == "Success"
| extend props = parse_json(Properties)
| extend entity = props.entity
| extend NIC = props.resource
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, NIC, entity
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
