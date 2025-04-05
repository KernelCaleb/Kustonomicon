```kusto
AuditLogs
| where OperationName == "Add owner to application"
| extend UserAgent = parse_json(AdditionalDetails)[0].value
| extend InitiatedBy_d = parse_json(InitiatedBy)
| extend
    initiatedBy_UPN = InitiatedBy_d.user.userPrincipalName,
    initiatedBy_IP = InitiatedBy_d.user.ipAddress
| extend TargetResources_d = parse_json(TargetResources)
| extend
    ApplicationClientId = TargetResources_d[0].modifiedProperties[0].newValue,
    ApplicationName = TargetResources_d[0].modifiedProperties[1].newValue,
    OwnerAdded = TargetResources_d[0].userPrincipalName
| where OwnerAdded contains "#EXT"
| project TimeGenerated, OperationName, initiatedBy_UPN, initiatedBy_IP, UserAgent, ApplicationClientId, ApplicationName, OwnerAdded, ResourceId
```