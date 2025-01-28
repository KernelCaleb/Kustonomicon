```kql
AuditLogs
| where OperationName == "Update named location"
| extend Caller = InitiatedBy.user.userPrincipalName
| extend CallerIpAddress = InitiatedBy.user.ipAddress
| mv-expand TargetResources
| extend NamedLocation = TargetResources.displayName
| extend modifiedProperties = TargetResources.modifiedProperties
| mv-expand modifiedProperties
| extend oldValue = modifiedProperties.oldValue
| extend newValue = modifiedProperties.newValue
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, NamedLocation, oldValue, newValue
```