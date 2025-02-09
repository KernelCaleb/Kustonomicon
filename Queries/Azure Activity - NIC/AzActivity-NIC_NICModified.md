```
AzureActivity
| where OperationNameValue contains "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE"
| where ActivityStatusValue == "Success"
| extend props = parse_json(Properties)
| extend entity = props.entity
| extend NIC = props.resource
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, NIC, entity
```