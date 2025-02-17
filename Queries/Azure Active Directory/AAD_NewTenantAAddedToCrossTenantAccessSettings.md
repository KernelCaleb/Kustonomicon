```kql
AuditLogs
| where OperationName == "Add a partner to cross-tenant access setting"
| extend parse_TargetResources = parse_json(TargetResources)
| extend NewTenant = parse_TargetResources[0].modifiedProperties[0].newValue
| extend parse_InitiatedBy = parse_json(InitiatedBy)
| extend Caller = parse_InitiatedBy.user.userPrincipalName
| extend CallerIpAddress = parse_InitiatedBy.user.ipAddress
| project TimeGenerated, OperationName, CorrelationId, Caller, CallerIpAddress, NewTenant
```