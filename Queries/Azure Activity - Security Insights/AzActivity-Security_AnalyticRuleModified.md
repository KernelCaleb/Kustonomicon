```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/WRITE"
| where ActivityStatusValue == "Success"
| extend parse_properties = parse_json(Properties)
| extend
    Resource = parse_properties.resource,
    ResourceGroup = parse_properties.resourceGroup,
    Subscription = parse_properties.subscriptionId,
    Entity = parse_properties.entity,
    AlertRuleGUID = split(tostring(parse_properties.resource), "/")[-1]
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, AlertRuleGUID, Entity
```