# Azure Activity - ST: Storage Account Container Deleted

### Description
This query detects when a Storage Account Container is deleted.

### Query
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/DELETE"
| where ActivityStatusValue == "Success"
| extend props = parse_json(Properties)
| extend entity = props.entity
| extend resource = props.resource
| extend array = split(resource, "/")
| extend StorageAccount = array[0]
| extend Container = array[2]
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, StorageAccount, Container, entity
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
