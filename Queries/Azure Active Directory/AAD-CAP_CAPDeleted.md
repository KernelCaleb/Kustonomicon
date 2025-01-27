# AAD - CAP: Conditional Access Policy Deleted

### Description
This query detects when a Conditional Access Policy has been deleted.

### Query
```kql
AuditLogs
| where OperationName == "Delete conditional access policy"
| extend InitiatingUPN = InitiatedBy.user.userPrincipalName
| extend IPAddress = InitiatedBy.user.ipAddress
| extend CAPName = TargetResources.[0].displayName
| extend CAPId = TargetResources.[0].id
| extend CAPValue = TargetResources.[0].modifiedProperties.[0].oldValue
| project TimeGenerated, CorrelationId, InitiatingUPN, IPAddress, CAPName, CAPId, CAPValue
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1556.009](https://attack.mitre.org/techniques/T1556/009/) | Modify Authentication Process: Conditional Access Policies | Credential Access, Defense Evasion, Presistence |

### Analytic Rule
- Yaml:
- ARM:

### Notes