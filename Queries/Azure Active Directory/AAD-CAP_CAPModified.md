# AAD - CAP: Conditional Access Policy Modified

### Description
This query detects changes to Conditional Access Policies. Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource.

### Query
```kql
AuditLogs
| where OperationName == "Update conditional access policy"
| extend InitiatingUPN = InitiatedBy.user.userPrincipalName
| extend IPAddress = InitiatedBy.user.ipAddress
| extend CAP = TargetResources.[0].displayName
| extend CAPId = TargetResources.[0].id
| extend NewCAP = TargetResources.[0].modifiedProperties.[0].newValue
| extend OldCAP = TargetResources.[0].modifiedProperties.[0].oldValue
| project TimeGenerated, CorrelationId, InitiatingUPN, IPAddress, CAP, CAPId, NewCAP, OldCAP
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1556.009](https://attack.mitre.org/techniques/T1556/009/) | Modify Authentication Process: Conditional Access Policies | Credential Access, Defense Evasion, Presistence |

### Analytic Rule
- Yaml: [AAD-CAP_CAPModified.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Active%20Directory/AAD-CAP_CAPModified.yaml)
- ARM: [AAD-CAP_CAPModified.json](https://github.com/KernelCaleb/KQL/blob/main/Analytic%20Rules/Azure%20Active%20Directory/AAD-CAP_CAPModified.json)

### Notes
This query can be helpful in detecting changes and misconfigurations in CAPs early. If the environment has frequent changes to CAPs then there can be some noise, however you can introduce filters in the query logic to remove detections from trusted `InitatingUPN` entities, or `CAPId` that are known to change frequently.
