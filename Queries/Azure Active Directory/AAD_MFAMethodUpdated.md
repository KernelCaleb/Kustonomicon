# AAD: Admin Modified MFA Method (phone)

### Description
This query detects when an administrator changes the phone based MFA method for a target account.

### Query
```kql
AuditLogs
| where OperationName == "Admin updated security info"
| where ResultDescription == "Admin changed phone method for user"
| extend parse_TargetResources = parse_json(TargetResources)
| extend
    Target = parse_TargetResources[0].userPrincipalName,
    AuthNumberOld = parse_TargetResources[0].modifiedProperties[2].oldValue,
    AuthNumberNew = parse_TargetResources[0].modifiedProperties[2].newValue
| extend parse_InitiatedBy = parse_json(InitiatedBy)
| extend
    Caller = tostring(parse_InitiatedBy.user.userPrincipalName),
    CallerIpAddress = parse_InitiatedBy.user.ipAddress
| where Caller != Target
| project TimeGenerated, CorrelationId, OperationName, ResultDescription, Caller, CallerIpAddress, Target, AuthNumberOld, AuthNumberNew
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes