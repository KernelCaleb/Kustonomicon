# AAD - MFA: Caller Adds MFA Method to Target Account

### Description
This query detects when a caller adds an MFA method to a separate target account.

### Query
```kql
AuditLogs
| where OperationName == "Admin registered security info"
| where ResultDescription == "Admin registered phone method for user"
| extend parse_TargetResources = parse_json(TargetResources)
| extend
    Target = parse_TargetResources[0].userPrincipalName,
    AuthMethodId = parse_TargetResources[0].modifiedProperties[0].newValue,
    AuthType = parse_TargetResources[0].modifiedProperties[1].newValue,
    PhoneNumber = parse_TargetResources[0].modifiedProperties[2].newValue
| extend parse_InitiatedBy = parse_json(InitiatedBy)
| extend Caller = tostring(parse_InitiatedBy.user.userPrincipalName)
| extend CallerIpAddress = parse_InitiatedBy.user.ipAddress
| where Caller != Target
| project TimeGenerated, CorrelationId, OperationName, ResultDescription, Caller, CallerIpAddress, Target, AuthMethodId, AuthType, PhoneNumber
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes