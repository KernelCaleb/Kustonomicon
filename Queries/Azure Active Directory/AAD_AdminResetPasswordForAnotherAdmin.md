# Azure AD: Administrator Password Reset by Another Administrator

### Description
This query detects when an administrator changes the password for another administrator.

### Query
```kql
AuditLogs
| where OperationName == "Reset password (by admin)"
| extend parse_InitiatedBy = parse_json(InitiatedBy)
| extend
    Caller = parse_InitiatedBy.user.userPrincipalName,
    CallerIpAddress = parse_InitiatedBy.user.ipAddress
| extend parse_TargetResources = parse_json(TargetResources)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| join kind=leftouter (
    IdentityInfo
    | where isnotempty(AccountUPN) and isnotempty(AssignedRoles)
    | project AccountUPN, AssignedRoles
) on $left.TargetUPN == $right.AccountUPN
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, TargetUPN, AssignedRoles
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
