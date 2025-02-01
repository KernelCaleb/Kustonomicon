# Azure AD - CAP: Named Location Modified

### Description
This query detects when a Named Location is modified, such as a new IP range is added to the Named Location.

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
| extend oldValue = modifiedProperties.oldValue
| extend newValue = modifiedProperties.newValue
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, NamedLocation, oldValue, newValue
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1556.009](https://attack.mitre.org/techniques/T1556/009/) | Modify Authentication Process: Conditional Access Policies | Credential Access, Defense Evasion, Presistence |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes