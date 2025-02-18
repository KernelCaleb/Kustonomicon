```kql
AuditLogs
| where OperationName == "Update a partner cross-tenant access setting"
| where Result == "success"
| extend parse_TargetResources = parse_json(TargetResources)
| extend ModifiedProperties = parse_TargetResources[0].modifiedProperties
| extend parse_InitiatedBy = parse_json(InitiatedBy)
| extend Caller = parse_InitiatedBy.user.userPrincipalName
| extend CallerIpAddress = parse_InitiatedBy.user.ipAddress
| project TimeGenerated, OperationName, CorrelationId, Caller, CallerIpAddress, ModifiedProperties
```