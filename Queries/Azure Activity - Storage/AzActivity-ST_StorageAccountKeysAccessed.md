```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
| where ActivityStatusValue == "Success"
| extend parse_Properties = parse_json(Properties)
| extend
    StorageAccount = parse_Properties.resource,
    Entity = parse_Properties.entity
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, StorageAccount, Entity
```