```kql
AuditLogs
| where OperationName == "Add member to role"
| extend parse_TargetResources = parse_json(TargetResources)
| extend
    Target_Type = parse_TargetResources[0].type,
    Target_DisplayName = parse_TargetResources[0].displayName
| where Target_Type == "Group"
| extend parse_ModifiedProperties = parse_json(parse_TargetResources[0].modifiedProperties)
| extend
    RoleTemplateId = trim("\"", tostring(parse_ModifiedProperties[2].newValue)),
    RoleDisplayName = trim("\"", tostring(parse_ModifiedProperties[1].newValue))
| extend parse_InitiatedBy = parse_json(InitiatedBy)
| extend
    Caller = parse_InitiatedBy.user.userPrincipalName,
    CallerIpAddress = parse_InitiatedBy.user.ipAddress
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, Target_DisplayName, RoleDisplayName, RoleTemplateId
```