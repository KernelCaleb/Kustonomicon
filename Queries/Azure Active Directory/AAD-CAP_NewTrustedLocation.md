# Azure AD - CAP: New Trusted Location Created

### Description
This query detects when a new Trusted Location has been created.

### Query
```kql
AuditLogs
| where OperationName == "Add named location"
| extend Caller = InitiatedBy.user.userPrincipalName
| extend CallerIpAddress = InitiatedBy.user.ipAddress
| mv-expand TargetResources
| extend modifiedProperties = TargetResources.modifiedProperties
| mv-expand modifiedProperties
| extend newValue = tostring(modifiedProperties.newValue)
| extend parsedNewValue = parse_json(newValue)
| extend displayName = tostring(parsedNewValue.displayName)
| extend cidrAddress = tostring(parsedNewValue.ipRanges[0].cidrAddress)
| extend isTrusted = tostring(parsedNewValue.isTrusted)
| where isTrusted == "true"
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, displayName, cidrAddress, isTrusted
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1556.009](https://attack.mitre.org/techniques/T1556/009/) | Modify Authentication Process: Conditional Access Policies | Credential Access, Defense Evasion, Presistence |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes