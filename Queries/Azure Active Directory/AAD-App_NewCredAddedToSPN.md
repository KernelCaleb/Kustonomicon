# AAD - App: New Credential Added to Azure AD Application

### Description
This query detects when an Azure AD App Registration has a new credential added. Adversaries may add adversary-controlled credentials to a cloud account, like an Azure AD app registration, in order to maintain persistent access to victim accounts and instances within the environment.

### KQL
```kql
AuditLogs
| where OperationName == "Update application – Certificates and secrets management "
| extend InitiatingUPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend IPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend UserAgent = tostring(AdditionalDetails[0].value)
| extend AppObjectId = tostring(TargetResources[0].id)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend CredentialAdded = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, CorrelationId, InitiatingUPN, IPAddress, UserAgent, AppObjectId, AppDisplayName, CredentialAdded
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation |

### Analytic Rule
- Yaml: [AAD-App_NewCredAddedToSPN.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Active%20Directory/AAD-App_NewCredAddedToSPN.json)
- ARM: [AAD-App_NewCredAddedToSPN.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Active%20Directory/AAD-App_NewCredAddedToSPN.json)

### Notes
