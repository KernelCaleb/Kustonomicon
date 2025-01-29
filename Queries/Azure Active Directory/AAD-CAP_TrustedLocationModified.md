# Azure AD - CAP: Trusted Location Modified

### Description
This query will detect when a trusted location is modified, or when a named location is marked as trusted.

### Query
```kql
AuditLogs
| where OperationName == "Update named location"
| extend Caller = InitiatedBy.user.userPrincipalName
| extend CallerIpAddress = InitiatedBy.user.ipAddress
| mv-expand TargetResources
| extend NamedLocation = TargetResources.displayName
| extend modifiedProperties = TargetResources.modifiedProperties
| mv-expand modifiedProperties
| extend oldValue = tostring(modifiedProperties.oldValue)
| extend newValue = tostring(modifiedProperties.newValue)
| extend parsedOldValue = parse_json(oldValue)
| extend parsedNewValue = parse_json(newValue)
| extend displayName = tostring(parsedOldValue.displayName)
| extend cidrAddress = tostring(parsedOldValue.ipRanges[0].cidrAddress)
| extend OldIsTrusted = tostring(parsedOldValue.isTrusted)
| extend NewIsTrusted = tostring(parsedNewValue.isTrusted)
| where OldIsTrusted == "true" or  NewIsTrusted == "true"
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, NamedLocation, oldValue, newValue
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes